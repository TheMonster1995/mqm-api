const express = require('express'),
  bodyParser = require('body-parser'),
  mongoose = require('mongoose'),
  cors = require('cors'),
  _ = require('lodash'),
  nodeMailer = require('nodemailer'),
  nodeCron = require('node-cron'),
  path = require('path'),
  spawn = require('child_process').spawn,
  multer = require('multer');

const { User, Item } = require('./models');

const {
  randomGenerator,
  sendResponse,
  isLoggedIn,
  isDefined,
  encrypt,
  decrypt,
  hash,
  emailRegex,
  cellRegex,
  sendEmail,
  handleDBQuery,
  generatePassword,
  idFixer,
  isAuthorized
} = require('./src/helper');

const {
  createJWT,
  checkJWT
} = require('./src/jwt');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads')
  },
  filename: function (req, file, cb) {
    const dt = new Date();
    cb(null, req.params?.userid ? `${req.params?.userid}_${file.filename ?? ''}${dt.toISOString()}${file.originalname.match(/\.[a-zA-Z0-9]*$/)[0]}` : file.fieldname)
  }
})

const upload = multer({ storage: storage })
//This needs security

const app = express();
mongoose.connect("mongodb://localhost/mqm");

app.set("view engine", "ejs");
app.set('views', path.join(__dirname, '/views'));
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json())
app.use(express.static("assets"));
app.use(cors());

app.get('/auth', async (req, res) => {
  let accessToken = req.headers.accesstoken;

  const result = await checkJWT(accessToken);

  if (result == 'error') return res.status(401).send({
    message: 'not_logged_in'
  });

  const user = await User.find({ user_id: result.data });
  const { username, user_id } = user[0];

  if (result != 'error')
    return sendResponse(res, 200, 'logged_in', { username, userid: user_id }, null);

  return res.status(401).send({
    message: 'not_logged_in'
  });
})

app.post('/login', async (req, res) => {

  let user = await User.find({ username: req.body.username.toLowerCase() });

  if (user.length == 0) return sendResponse(res, 400, 'user_not_exist', null, 'user_does_not_exist');

  user = user[0];

  const password = hash(decrypt(req.body.password, 'client'));
  const uPassword = decrypt(user.password, 'api');

  if (password != uPassword) return sendResponse(res, 400, 'wrong_password', null, 'wrong_password');

  if (user.status == 'inactive') return sendResponse(res, 401, 'user_inactive', null, 'user_inactive');

  const accessToken = createJWT({ data: user.user_id }, '2h');

  return sendResponse(
    res,
    200,
    'logged_in',
    {
      accessToken,
      username: user.username,
      userid: user.user_id,
    },
    null
  );
})

app.get('/items/:userid', isAuthorized, async (req, res) => {
  const user = await User.find({ user_id: req.params.userid });
  let item = await Item.find({ item_id: user[0].item });
  console.log(item);
  item = item[0];

  console.log(user);
  console.log(item);

  return sendResponse(
    res,
    200,
    'getting_items',
    {
      items: user.items,
      default: {
        path: item.path,
        size: item.size,
        name: item.filename,
        fieldName: item.fieldname,
      },
    },
    null,
  );
})

app.get('/item/:userid', async (req, res) => {
  const user = await User.find({ user_id: req.params.userid });
  const item = await Item.find({ item_id: user[0]?.item });

  return sendResponse(res, 200, 'getting_item', item[0], null);
})

app.get('/preview/:userid', async (req, res) => {
  const user = await User.find({ user_id: req.params.userid });
  const item = await Item.find({ item_id: user[0]?.item });

  res.sendFile(path.join(__dirname, `./${item[0]?.path}`));
})

app.put('/item/:userid', isAuthorized, async (req, res) => {
  await User.updateOne(
    { user_id: req.params.userid },
    { $set: { item: req.body.default } }
  )

  return sendResponse(res, 200, 'item_updated', null, null)
})

app.get('/password/forgot/link', async (req, res) => {
  let userMail = req.headers.usermail;

  let user = await User.find({ email: userMail });

  if (!user || user.length == 0) return sendResponse(res, 400, 'user_not_exist', null, 'user_does_not_exist');

  if (user[0].status == 'inactive') return sendResponse(res, 401, 'user_inactive', null, 'user_inactive');

  let fpToken = await createJWT({ userid: user[0].user_id }, '2h');

  try {
    await sendEmail(user[0].email, 'fp', fpToken);
  } catch (err) {
    return sendResponse(res, 500, 'send_mail_failed', null, 'send_mail_failed');
  }

  return sendResponse(res, 200, 'reset_link_sent', null, null);
})

app.get('/password/forgot', async (req, res) => {
  let token = req.headers.forgottoken;

  token = await checkJWT(token)

  if (token == 'error') return sendResponse(res, 400, 'invalid_token', null, 'invalid_forgot_token');

  let newToken = await createJWT({ userid: token.userid, key: 'forgotpassword' }, '2h');

  return sendResponse(res, 200, 'token_generated', newToken, null);
})

app.post('/password/forgot', async (req, res) => {
  let token = req.headers.forgottoken;

  token = await checkJWT(token)

  if (token == 'error' || token.key != 'forgotpassword') return sendResponse(res, 400, 'invalid_token', null, 'invalid_forgot_token');

  let user = await User.find({ user_id: token.userid })
  user = user[0];

  let newPassword = await encrypt(hash(decrypt(req.body.newpassword, 'client')), 'api');
  user.password = newPassword;

  user.save();

  let accessToken = await createJWT({ data: user.user_id, cafe_id: user.cafe_id }, '2h');

  return sendResponse(
    res,
    200,
    'password_reset',
    {
      accessToken,
      username: user.username,
      name: user.name,
      userid: user.user_id,
    },
    null
  )
})

app.put('/password', isLoggedIn, async (req, res) => {

  let token = await checkJWT(req.headers.accesstoken)

  let user = await User.find({ user_id: token.data });
  user = user[0];

  let newPassword = await encrypt(hash(decrypt(req.body.newpassword, 'client')), 'api');
  user.password = newPassword;

  user.save();

  return sendResponse(res, 200, 'password_changed', null, null);
})

app.post('/upload/:userid', isAuthorized, upload.single('userItem'), async (req, res) => {
  const user_id = req.params.userid;
  const file = req.file;
  if (!file) return sendResponse(res, 400, 'error_uploading_file', null, 'error_uploading_file');
  const newItem = {
    item_id: randomGenerator(6),
    path: file.path,
    size: file.size,
    name: file.filename,
    fieldName: file.fieldname,
  };

  await Item.create(newItem);

  await User.updateOne(
    { user_id },
    { $set: { item: newItem.item_id } }
  );

  sendResponse(
    res,
    200,
    'file_uploaded',
    newItem,
    null,
  );
});

const port = process.env.PORT || 4080;

const backUp = async () => {
  console.log('backup called');
  let backupProcess = spawn('mongodump', [
    '--db=ham_cafe',
    '--archive=.',
    '--gzip'
  ]);

  backupProcess.on('exit', (code, signal) => {
    if (code)
      console.log('Backup process exited with code ', code);
    else if (signal)
      console.error('Backup process was killed with singal ', signal);
    else
      console.log('Successfully backedup the database')
  });
}

const injectUser = async (name, username) => {
  console.log('inject user called');

  const password = '12346578';
  const user_id = randomGenerator(6);

  const encPassword = await encrypt(hash(password), 'api');

  const userData = {
    user_id,
    role: 'admin',
    signup_date: new Date(),
    email: '',
    username,
    name,
    status: 'active',
    password: encPassword,
  };

  const newUser = await User.create(userData);

  return user_id;
}

app.listen(port, async () => {
  console.log("Server is listening on port: ", port);
  let dbBackupTask = nodeCron.schedule('37 20 * * *', backUp);
  // const adminId = await injectUser('Parsa', 'parsa_t');
  // injectCafe(name, cafe_id, adminId);
  // dbIdFixer();
  // indexFixer();
  // DANGER //
  // MENU INIT //
  // initData();
  // initUser();
  // DANGER //
})

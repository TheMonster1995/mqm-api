const express 		= require('express'),
  bodyParser 			= require('body-parser'),
  mongoose 				= require('mongoose'),
  cors						= require('cors'),
  _               = require('lodash'),
  nodeMailer      = require('nodemailer'),
  nodeCron        = require('node-cron'),
  path            = require('path'),
  spawn           = require('child_process').spawn,
  multer          = require('multer');

const { User } = require('./models');

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
    cb(null, req.params?.itemid ? `${req.params?.cafeid}_${req.params?.itemid}${file.originalname.match(/\.[a-zA-Z0-9]*$/)[0]}` : file.fieldname)
  }
})
 
const upload = multer({ storage: storage })
//This needs security

const app = express();
mongoose.connect("mongodb://localhost/easemtest");

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

  const user = await User.find({user_id: result.data});
  const { username } = user[0];

  if (result != 'error')
    return sendResponse(res, 200, 'logged_in', { username }, null);

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
    },
    null
  );
})

app.get('/items/:userid', isAuthorized, async (req, res) => {
  const user = await User.find({ user_id: req.params.userid });

  return sendResponse(res, 200, 'getting_items', { items: user.items, default: user.item }, null);
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

  let user = await User.find({email: userMail});

  if (!user || user.length == 0) return sendResponse(res, 400, 'user_not_exist', null, 'user_does_not_exist');

  if (user[0].status == 'inactive') return sendResponse(res, 401, 'user_inactive', null, 'user_inactive');

  let fpToken = await createJWT({userid: user[0].user_id}, '2h');

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

  let newToken = await createJWT({userid: token.userid, key: 'forgotpassword'}, '2h');

  return sendResponse(res, 200, 'token_generated', newToken, null);
})

app.post('/password/forgot', async (req, res) => {
  let token = req.headers.forgottoken;

  token = await checkJWT(token)

  if (token == 'error' || token.key != 'forgotpassword') return sendResponse(res, 400, 'invalid_token', null, 'invalid_forgot_token');

  let user = await User.find({user_id: token.userid})
  user = user[0];

  let newPassword = await encrypt(hash(decrypt(req.body.newpassword, 'client')), 'api');
  user.password = newPassword;

  user.save();

  let accessToken = await createJWT({data: user.user_id, cafe_id: user.cafe_id}, '2h');

  return sendResponse(
    res,
    200,
    'password_reset',
    {
      accessToken,
      username: user.username,
      name: user.name
    },
    null
  )
})

app.put('/password', isLoggedIn, async (req, res) => {

  let token = await checkJWT(req.headers.accesstoken)

  let user = await User.find({user_id: token.data});
  user = user[0];

  let newPassword = await encrypt(hash(decrypt(req.body.newpassword, 'client')), 'api');
  user.password = newPassword;

  user.save();

  return sendResponse(res, 200, 'password_changed', null, null);
})

app.get('/menu/:cafeid', async (req, res) => {
  let menu = [],
    cafe_id = req.params.cafeid,
    cats = await Category.find({ cafe_id });

  for (let i = 0; i < cats.length; i++) {
    let items = [],
      cat = cats[i];

    items = await Item.find({cat: cat.cat_id, cafe_id: cafe_id});
    // for (let j = 0; j < cat.children.length; j++) {
    //   let item = await Item.find({cat: cat.cat_id});
    //   items.push(item[0]._doc);
    // }
    menu.push({
      ...cat._doc,
      children: items
    })
  }

  return sendResponse(res, 200, 'get_menu', menu, null)
})

app.post('/cat/new/:cafeid', isAuthorized, async (req, res) => {
  const cafe_id = req.params.cafeid;
  let cats = await Category.find({ cafe_id });

  let activeCats = cats.filter(cat => cat.status != 'archived').length;

  const catData = {
    ...req.body,
    active: true,
    cat_id: idFixer(cats.length + 1, 3),
    children: [],
    status: 'created',
    index: activeCats,
    cafe_id
  };

  await Category.create(catData);

  return sendResponse(res, 200, 'category_created', { catId: catData.cat_id }, null);
})

app.put('/cat/:cafeid', isAuthorized, async (req, res) => {
  const cafe_id = req.params.cafeid;
  await Category.updateOne(
    { cat_id: req.body.catid, cafe_id },
    { $set: { ...req.body.catdata } }
  )
  if (!req.body.indexdata) return sendResponse(res, 200, 'cat_updated', null, null);

  let indexData = req.body.indexdata;

  for (let i = 0; i < indexData.length; i++) {
    await Category.updateOne(
      { cat_id: `${indexData[i].cat_id}`, cafe_id },
      { $set: { index: `${indexData[i].index}` } }
    )
  }

  return sendResponse(res, 200, 'cat_updated', null, null)
})

app.delete('/cat/:catid/:cafeid', isAuthorized, async (req, res) => {
  const cafe_id = req.params.cafeid;
  let cat = await Category.find({ cat_id: req.params.catid, cafe_id });

  if (cat[0].children.length > 0) return sendResponse(res, 409, 'cat_has_children', null, 'cat_has_children');

  await Category.deleteOne({ cat_id: req.params.catid, cafe_id });

  return sendResponse(res, 200, 'cat_deleted', null, null);
})

app.post('/item/new/:cafeid', isAuthorized, async (req, res) => {
  const cafe_id = req.params.cafeid;
  let cat = await Category.find({ cat_id: req.body.cat, cafe_id });

  let children = cat[0].children,
    activeChildren = children.filter(child => child.status != 'archived').length;

  const itemData = {
    ...req.body,
    active: true,
    status: 'created',
    item_id: `${cat[0].cat_id}-${idFixer(children.length + 1, 3)}`,
    index: activeChildren,
    cafe_id
  };

  await Item.create(itemData);

  await Category.updateOne(
    { cat_id: req.body.cat, cafe_id },
    { $set: { children: [...children, itemData.item_id] } }
  )

  return sendResponse(res, 200, 'item_created', { itemId: itemData.item_id }, null);
})

app.put('/item/:cafeid', isAuthorized, async (req, res) => {
  const cafe_id = req.params.cafeid;
  await Item.updateOne(
    { item_id: req.body.itemid, cafe_id },
    { $set: { ...req.body.itemdata } }
  )

  return sendResponse(res, 200, 'item_updated', null, null)
})

app.post('/item/img/:itemid/:cafeid', isAuthorized, upload.single('itemImg'), async (req, res) => {
  const cafe_id = req.params.cafeid;
  const file = req.file;
  if (!file) return sendResponse(res, 400, 'error_uploading_file', null, 'error_uploading_file');

  await Item.updateOne(
    { item_id: req.params.itemid, cafe_id },
    { $set: { img: file.path } }
  );

  sendResponse(res, 200, 'img_updated', file.path, null);
});

app.delete('/item/:itemid/:cafeid', isAuthorized, async (req, res) => {
  const cafe_id = req.params.cafeid;
  let item = await Item.find({ item_id: req.params.itemid, cafe_id })
  let cat = await Category.find({ cat_id: item[0].cat, cafe_id });
  let children = cat[0].children.filter(child => child != item[0].item_id);

  await Category.updateOne(
    { cat_id: req.body.catid, cafe_id },
    { $set: { children } }
  )

  await Item.deleteOne({ item_id: req.params.itemid, cafe_id });

  return sendResponse(res, 200, 'item_deleted', null, null);
})

const port = process.env.PORT || 4010;

const initData = async () => {
  let cat, item, children, items;
  console.log('IT BEGINS');
  const data = [
    {
      cat_id: '001',
      cafe_id: 'ham_asa',
      label: 'قهوه گرم',
      active: true,
      children: [
        {
          item_id: '001-001',
          cafe_id: 'ham_asa',
          label: 'ریستریتو',
          desc: '',
          price: '26',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-002',
          cafe_id: 'ham_asa',
          label: 'اسپرسو',
          desc: '',
          price: '26',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-003',
          cafe_id: 'ham_asa',
          label: 'دوپیو',
          desc: '',
          price: '30',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-004',
          cafe_id: 'ham_asa',
          label: 'لانگو',
          desc: '',
          price: '30',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-005',
          cafe_id: 'ham_asa',
          label: 'جیبرالتار',
          desc: '',
          price: '38',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-006',
          cafe_id: 'ham_asa',
          label: 'کاپوچینو',
          desc: '',
          price: '40',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-007',
          cafe_id: 'ham_asa',
          label: 'کافه لاته',
          desc: '',
          price: '40',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-008',
          cafe_id: 'ham_asa',
          label: 'کن پانا',
          desc: '',
          price: '35',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-009',
          cafe_id: 'ham_asa',
          label: 'اسپرسو ماکیاتو',
          desc: '',
          price: '35',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-010',
          cafe_id: 'ham_asa',
          label: 'لته ماکیاتو',
          desc: '',
          price: '46',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-011',
          cafe_id: 'ham_asa',
          label: 'هات چاکلت',
          desc: '',
          price: '35',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-012',
          cafe_id: 'ham_asa',
          label: 'وایت چاکلت',
          desc: '',
          price: '35',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-013',
          cafe_id: 'ham_asa',
          label: 'موکا',
          desc: '',
          price: '46',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
        {
          item_id: '001-014',
          cafe_id: 'ham_asa',
          label: 'شات سیروپ',
          desc: 'سوال کنید',
          price: '5',
          cat_label: 'قهوه گرم',
          cat: '001',
          active: true,
          status: 'created'
        },
      ]
    },
    {
      cat_id: '002',
      cafe_id: 'ham_asa',
      label: 'قهوه سرد',
      active: true,
      children: [
        {
          item_id: '002-001',
          cafe_id: 'ham_asa',
          label: 'آیس لته',
          desc: '',
          price: '40',
          cat_label: 'قهوه سرد',
          cat: '002',
          active: true,
          status: 'created'
        },
        {
          item_id: '002-002',
          cafe_id: 'ham_asa',
          label: 'آیس آمریکانو',
          desc: '',
          price: '33',
          cat_label: 'قهوه سرد',
          cat: '002',
          active: true,
          status: 'created'
        },
        {
          item_id: '002-003',
          cafe_id: 'ham_asa',
          label: 'فراپاچینو',
          desc: '',
          price: '50',
          cat_label: 'قهوه سرد',
          cat: '002',
          active: true,
          status: 'created'
        },
        {
          item_id: '002-004',
          cafe_id: 'ham_asa',
          label: 'آفوگاتو',
          desc: '',
          price: '35',
          cat_label: 'قهوه سرد',
          cat: '002',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '003',
      cafe_id: 'ham_asa',
      label: 'چای و دمنوش',
      active: true,
      children: [
        {
          item_id: '003-001',
          cafe_id: 'ham_asa',
          label: 'چای آولانگ',
          desc: '',
          price: '30',
          cat_label: 'cat label',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-002',
          cafe_id: 'ham_asa',
          label: 'چای سبز',
          desc: '',
          price: '30',
          cat_label: 'cat label',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-003',
          cafe_id: 'ham_asa',
          label: 'چای سیاه',
          desc: 'دودی',
          price: '28',
          cat_label: 'cat label',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-004',
          cafe_id: 'ham_asa',
          label: 'چای سیاه',
          desc: '',
          price: '20',
          cat_label: 'cat label',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-005',
          cafe_id: 'ham_asa',
          label: 'چای زعفران',
          desc: '',
          price: '32',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-006',
          cafe_id: 'ham_asa',
          label: 'چای ماسالا',
          desc: '',
          price: '35',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-007',
          cafe_id: 'ham_asa',
          label: 'رویبوس',
          desc: 'دمنوش',
          price: '35',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-008',
          cafe_id: 'ham_asa',
          label: 'میوه‌های بری',
          desc: 'دمنوش',
          price: '35',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-009',
          cafe_id: 'ham_asa',
          label: 'قوری چای سیاه',
          desc: '',
          price: '38',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-010',
          cafe_id: 'ham_asa',
          label: 'قوری چای رعفران',
          desc: '',
          price: '45',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-011',
          cafe_id: 'ham_asa',
          label: 'قوری چای سبز',
          desc: '',
          price: '45',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        },
        {
          item_id: '003-012',
          cafe_id: 'ham_asa',
          label: 'قوری چای سیاه',
          desc: 'دودی',
          price: '44',
          cat_label: 'چای و دمنوش',
          cat: '003',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '004',
      cafe_id: 'ham_asa',
      label: 'کیک',
      active: true,
      children: [
        {
          item_id: '004-001',
          cafe_id: 'ham_asa',
          label: 'کیک روز',
          desc: '',
          price: '38',
          cat_label: 'کیک',
          cat: '004',
          active: true,
          status: 'created'
        },
        {
          item_id: '004-002',
          cafe_id: 'ham_asa',
          label: 'چیزکیک',
          desc: '',
          price: '40',
          cat_label: 'کیک',
          cat: '004',
          active: true,
          status: 'created'
        },
        {
          item_id: '004-003',
          cafe_id: 'ham_asa',
          label: 'جارکیک',
          desc: '',
          price: '40',
          cat_label: 'کیک',
          cat: '004',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '005',
      cafe_id: 'ham_asa',
      label: 'نوشیدنی سرد',
      active: true,
      children: [
        {
          item_id: '005-001',
          cafe_id: 'ham_asa',
          label: 'مونگه',
          desc: 'انبه، زردآلو، پشن فروت',
          price: '45',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-002',
          cafe_id: 'ham_asa',
          label: 'مو/سی/تو',
          desc: 'آلبالو، گیلاس، تمشک، سودا',
          price: '40',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-003',
          cafe_id: 'ham_asa',
          label: 'دینگو',
          desc: 'لیمو، آب پرتقال، بلوکروسائو',
          price: '42',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-004',
          cafe_id: 'ham_asa',
          label: 'نیلگون',
          desc: 'لیمو، تخم شربتی، آلوئه‌ورا',
          price: '40',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-005',
          cafe_id: 'ham_asa',
          label: 'شیله',
          desc: 'هندوانه، لیمو، توت فرنگی',
          price: '45',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-006',
          cafe_id: 'ham_asa',
          label: 'موهیتو',
          desc: '',
          price: '35',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-007',
          cafe_id: 'ham_asa',
          label: 'رد موهیتو',
          desc: '',
          price: '38',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-008',
          cafe_id: 'ham_asa',
          label: 'لیموناد',
          desc: '',
          price: '32',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        },
        {
          item_id: '005-009',
          cafe_id: 'ham_asa',
          label: 'لیموناد سیب',
          desc: '',
          price: '36',
          cat_label: 'نوشیدنی سرد',
          cat: '005',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '006',
      cafe_id: 'ham_asa',
      label: 'شیک و اسموتی',
      active: true,
      children: [
        {
          item_id: '006-001',
          cafe_id: 'ham_asa',
          label: 'شیک موز پسته',
          desc: '',
          price: '54',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-002',
          cafe_id: 'ham_asa',
          label: 'شیک بادام زمینی',
          desc: '',
          price: '54',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-003',
          cafe_id: 'ham_asa',
          label: 'شیک توت فرنگی',
          desc: '',
          price: '49',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-004',
          cafe_id: 'ham_asa',
          label: 'شیک شکلاتی',
          desc: '',
          price: '45',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-005',
          cafe_id: 'ham_asa',
          label: 'شیک شوکو بیسکوئیت',
          desc: '',
          price: '49',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-006',
          cafe_id: 'ham_asa',
          label: 'شیک قهوه',
          desc: '',
          price: '54',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-007',
          cafe_id: 'ham_asa',
          label: 'اسموتی تمشک آلبالو',
          desc: '',
          price: '45',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-008',
          cafe_id: 'ham_asa',
          label: 'اسموتی توت فرنگی',
          desc: '',
          price: '45',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        },
        {
          item_id: '006-009',
          cafe_id: 'ham_asa',
          label: 'اسموتی انبه شاه‌توت',
          desc: '',
          price: '45',
          cat_label: 'شیک و اسموتی',
          cat: '006',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '007',
      cafe_id: 'ham_asa',
      label: 'پیش غذا',
      active: true,
      children: [
        {
          item_id: '007-001',
          cafe_id: 'ham_asa',
          label: 'سیب‌زمینی',
          desc: '',
          price: '40',
          cat_label: 'پیش غذا',
          cat: '007',
          active: true,
          status: 'created'
        },
        {
          item_id: '007-002',
          cafe_id: 'ham_asa',
          label: 'سیب‌زمینی با بیکن',
          desc: '',
          price: '59',
          cat_label: 'پیش غذا',
          cat: '007',
          active: true,
          status: 'created'
        },
        {
          item_id: '007-003',
          cafe_id: 'ham_asa',
          label: 'سیب‌زمینی با سس قارچ',
          desc: '',
          price: '58',
          cat_label: 'پیش غذا',
          cat: '007',
          active: true,
          status: 'created'
        },
        {
          item_id: '007-004',
          cafe_id: 'ham_asa',
          label: 'سالاد سزار',
          desc: 'کاهو رسی، نان سیر، پارمسان، مرع گریل، بیبی کورن، زیتون، سس سزار',
          price: '78',
          cat_label: 'پیش غذا',
          cat: '007',
          active: true,
          status: 'created'
        },
        {
          item_id: '007-005',
          cafe_id: 'ham_asa',
          label: 'سالاد کینوا',
          desc: 'کاهوپیچ، کیپرز، ترتیلا',
          price: '60',
          cat_label: 'پیش غذا',
          cat: '007',
          active: true,
          status: 'created'
        },
        {
          item_id: '007-006',
          cafe_id: 'ham_asa',
          label: 'سالاد بروکلی',
          desc: 'کاهو فرانسه، کاهوپیچ، پنیر دودی، ریحان، بروکلی',
          price: '52',
          cat_label: 'پیش غذا',
          cat: '007',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '008',
      cafe_id: 'ham_asa',
      label: 'غذا',
      active: true,
      children: [
        {
          item_id: '008-001',
          cafe_id: 'ham_asa',
          label: 'همـ/برگر',
          desc: '150 گرم گوشت، سس مخصوص، سیب زمینی',
          price: '78',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-002',
          cafe_id: 'ham_asa',
          label: 'کینوا برگر',
          desc: 'گیاهی',
          price: '60',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-003',
          cafe_id: 'ham_asa',
          label: 'چیزبرگر',
          desc: '150 گرم گوشت، پنیر گودا، سس مخصوص، سیب زمینی',
          price: '84',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-004',
          cafe_id: 'ham_asa',
          label: 'سوجوک برگر',
          desc: '150 گرم گوشت، پنیر گودا، سوسیس سوجوک، سس مخصوص',
          price: '94',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-005',
          cafe_id: 'ham_asa',
          label: 'فیله برگر',
          desc: '150 گرم فیله مرغ گریل شده، سس مخصوص، سیب زمینی',
          price: '62',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-006',
          cafe_id: 'ham_asa',
          label: 'گریل مرغ',
          desc: '250 تا 300 گرم سینه مرغ گریل، پوره سیب‌زمینی، دورچین سبزیجات، سس قارچ',
          price: '92',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-007',
          cafe_id: 'ham_asa',
          label: 'پاستا پینتوریکو',
          desc: '200 گرم پنه، سس پینتوریکو، 120 گرم مرغ، 80 گرم قارچ',
          price: '69',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        },
        {
          item_id: '008-008',
          cafe_id: 'ham_asa',
          label: 'ماکارانی سبزیجات',
          desc: '200 گرم ماکارانی رشته، سس گوجه، سبزیجات',
          price: '55',
          cat_label: 'غذا',
          cat: '008',
          active: true,
          status: 'created'
        }
      ]
    },
    {
      cat_id: '009',
      cafe_id: 'ham_asa',
      label: 'صبحانه',
      active: true,
      children: [
        {
          item_id: '009-001',
          cafe_id: 'ham_asa',
          label: 'بشقاب ایرلندی',
          desc: 'تخم مرغ، بیکن، نان تست، قارچ، گوجه گیلاسی، دورچین میوه',
          price: '68',
          cat_label: 'cat label',
          cat: '009',
          active: true,
          status: 'created'
        },
        {
          item_id: '009-002',
          cafe_id: 'ham_asa',
          label: 'املت ایرانی',
          desc: '',
          price: '39',
          cat_label: 'cat label',
          cat: '009',
          active: true,
          status: 'created'
        },
        {
          item_id: '009-003',
          cafe_id: 'ham_asa',
          label: 'پنیر برشته',
          desc: 'پنیر تبریزی برشته، دو عدد تخم‌مرغ، ادویه مخصوص',
          price: '35',
          cat_label: 'cat label',
          cat: '009',
          active: true,
          status: 'created'
        },
        {
          item_id: '009-004',
          cafe_id: 'ham_asa',
          label: 'بشقاب هم',
          desc: '',
          price: '105',
          cat_label: 'cat label',
          cat: '009',
          active: true,
          status: 'created'
        },
        {
          item_id: '009-005',
          cafe_id: 'ham_asa',
          label: 'وافل',
          desc: '',
          price: '57',
          cat_label: 'cat label',
          cat: '009',
          active: true,
          status: 'created'
        },
        {
          item_id: '009-006',
          cafe_id: 'ham_asa',
          label: 'نیمرو بیکن',
          desc: '',
          price: '45',
          cat_label: 'cat label',
          cat: '009',
          active: true,
          status: 'created'
        }
      ]
    }
  ];
  for (let i = 0; i < data.length; i++) {
    cat = data[i];
    items = [...cat.children];
    cat.children = [];
    console.log('cat started: ', cat.cat_id);
    for (let j = 0; j < items.length; j++) {
      item = items[j];
      console.log('item: ', item.item_id);
      await Item.create(item);
      console.log('item created');
      cat.children.push(item.item_id)
    }
    console.log('children finished');
    console.log('cat: ', cat.cat_id);
    await Category.create(cat)
    console.log('cat created');
  }

  console.log('IT ENDS');
}

const initUser = async () => {
  console.log("USER INIT");
  const password = '12346578';

  const encPassword = await encrypt(hash(password), 'api');

  const userData = {
    user_id: randomGenerator(6),
    role: 'admin',
    signup_date: new Date(),
    email: 'salmanian.foad2@gmail.com',
  	username: 'admin',
    name: 'Admin',
    status: 'active',
    password: encPassword
  };

  const newUser = await User.create(userData);
  console.log("USER CREATED");
}

const backUp = async () => {
  console.log('backup called');
  let backupProcess = spawn('mongodump', [
      '--db=ham_cafe',
      '--archive=.',
      '--gzip'
      ]);

  backupProcess.on('exit', (code, signal) => {
      if(code)
          console.log('Backup process exited with code ', code);
      else if (signal)
          console.error('Backup process was killed with singal ', signal);
      else
          console.log('Successfully backedup the database')
  });
}

const dbIdFixer = async () => {
  console.log('id fixer called');

  const cats = await Category.find({status: {$nin: ['archived']}})

  for (let i = 0; i < cats.length; i++) {
    const cat = cats[i];
    let newChildren = [];
    console.log('in Cat')
    console.log(cat);

    for (let j = 0; j < cat.children.length; j++) {
      console.log('in children')
      console.log(cat.children[j]);

      const item_id = `${idFixer(i + 1, 3)}-${idFixer(j + 1, 3)}`;
      await Item.updateOne({cat_id: cat.cat_id, item_id: cat.children[j]}, {$set: {item_id}})
      newChildren.push(item_id);
    }
    console.log(newChildren);
    await Category.updateOne({cat_id: cat.cat_id}, {$set: {children: newChildren}})
  }

  console.log('id fixer finished');
}

const indexFixer = async () => {
  console.log('index fixer called');

  const cats = await Category.find({status: {$nin: ['archived']}});
  console.log('before');
  console.log(cats);

  for (let i = 0; i < cats.length; i++) {
    console.log('in');
    console.log(cats[i]);
    await Category.updateOne({cat_id: cats[i].cat_id}, {$set:{index: i}})
  }

  console.log('out and done');
}

const injectCafe = async (name, cafe_id, admin, others = {}) => {
  console.log('inject cafe called');

  const newCafe = {
    name,
    cafe_id,
    admin,
    signup_date: `${new Date().toDateString()}`,
    ...others
  }

  console.log(newCafe);

  const justtesting = await Cafe.create(newCafe);

  console.log(justtesting);
  console.log('cafe created');
}

const injectUser = async (name, cafe_id) => {
  console.log('inject user called');

  const password = '12346578';
  const user_id = randomGenerator(6);

  const encPassword = await encrypt(hash(password), 'api');

  const userData = {
    user_id,
    role: 'admin',
    signup_date: new Date(),
    email: '',
  	username: cafe_id,
    name,
    status: 'active',
    password: encPassword,
    cafe_id,
  };

  const newUser = await User.create(userData);

  return user_id;
}

app.listen(port, async () => {
	console.log("Server is listening on port: ", port);
  let dbBackupTask = nodeCron.schedule('37 20 * * *', backUp);
  // const name = 'سان',
  //   cafe_id = 'sun';
  // const name = 'هم/آسا',
  //   cafe_id = 'ham_asa';
  // const adminId = await injectUser(name, cafe_id);
  // injectCafe(name, cafe_id, adminId);
  // dbIdFixer();
  // indexFixer();
  // DANGER //
  // MENU INIT //
  // initData();
  // initUser();
  // DANGER //
})


// function o2 (a) {if (a.length > 2) return Math.max(o2(a.slice(0, a.length / 2)), o2(a.slice(a.length))); return Math.max(a[0], a[1] || 0)}
//
// var sample = [59, 10, 52, 61, 51, 18, 1, 35, 25, 88, 20, 93, 81, 64, 1, 56];
//
// function o2 (arr) {
//   console.log('o2 start:  ', arr);
//   if (arr.length > 2) {
//     var arr1 = arr.slice(0, Math.floor(arr.length / 2));
//     var arr2 = arr.slice(Math.floor(arr.length / 2));
//     var res1 = o2(arr1);
//     var res2 = o2(arr2);
//
//     console.log('o2 end:  ', arr);
//     return (Math.max(res1, res2))
//   }
//
//   console.log('o2 end:  ', arr);
//   return (Math.max(arr[0], arr[1]))
// }

// app.get('/users', isLoggedIn, async (req, res) => {
  //   let users = await User.find({});
  
  //   users = users.map(user => ({
  //     user_id: user.user_id,
  //     name: user.name,
  //     email: user.email,
  //     username: user.username,
  //     role: user.role,
  //     status: user.status
  //   }))
  
  //   return sendResponse(res, 200, 'getting_users', users, null);
  // })
  
  // app.post('/user/new', isLoggedIn, async (req, res) => {
  //   let authToken = await checkJWT(req.headers.accesstoken);
  
  //   if (authToken == 'error' || authToken.role != 'admin') return sendResponse(res, 400, 'invalid_request', null, 'token_invalid');
  
  //   const password = decrypt(req.body.user.password, 'client');
  
  //   const encPassword = await encrypt(hash(password), 'api');
  
  //   const userData = {
  //     user_id: randomGenerator(6),
  //     role: req.body.user.role || 'admin',
  //     signup_date: new Date(),
  //     email: req.body.user.email || '',
  //   	username: req.body.user.username.toLowerCase() || '',
  //     name: req.body.user.name || '',
  //     status: req.body.user.status || 'active',
  //     password: encPassword
  //   };
  
  //   const newUser = await User.create(userData);
  
  //   sendEmail(userData.email, 'newUser', {username: userData.username, password});
  
  //   return sendResponse(res, 200, 'logged_in', {userId: userData.user_id}, null);
  // })
  
  // app.put('/user', isLoggedIn, async (req, res) => {
  //   let authToken = await checkJWT(req.headers.accesstoken);
  
  //   if (authToken == 'error' || authToken.role != 'admin') return sendResponse(res, 400, 'invalid_request', null, 'token_invalid');
  
  //   await User.updateOne(
  //     { user_id: req.body.userid },
  //     { $set: { ...req.body.userdata } }
  //   )
  
  //   return sendResponse(res, 200, 'user_updated', {userId: req.body.userid}, null)
  // })
  
  // app.delete('/user/:userid', isLoggedIn, async (req, res) => {
  //   let authToken = await checkJWT(req.headers.accesstoken);
  
  //   if (authToken == 'error' || authToken.role != 'admin') return sendResponse(res, 400, 'invalid_request', null, 'token_invalid');
  
  //   await User.deleteOne({ user_id: req.params.userid });
  
  //   return sendResponse(res, 200, 'user_deleted', null, null)
  // })
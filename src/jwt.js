const jwt = require('jsonwebtoken');
const config = require('../config.json');

module.exports = {
  createJWT: (data, expireTime) => {
    return jwt.sign(data, config.secret, { expiresIn: expireTime });
  },

  checkJWT: async token => {
    return await jwt.verify(token, config.secret, (err, decoded) => {
  		if (err) {
        console.log(err);
  			return 'error';
  		}

  		return decoded;
  	})
  }
}

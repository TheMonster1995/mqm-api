const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
	user_id: String,
	password: String,
	email: String,
	role: String,
	status: String,
	username: String,
	signup_date: Date,
  title: String,
  item: String,
  items: Array,
})

const User = mongoose.model("User", userSchema);

module.exports = User;

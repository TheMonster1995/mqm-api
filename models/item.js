const mongoose = require('mongoose');

const itemSchema = mongoose.Schema({
  item_id: String,
  path: String,
  size: String,
  name: String,
  fieldName: String,
})

const Item = mongoose.model("Item", itemSchema);

module.exports = Item;

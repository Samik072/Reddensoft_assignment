const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true },
  phone:     { type: String, required: true },
  password:  { type: String, required: true },
  verified:  { type: Boolean, default: false },
  verifyToken: String
});
module.exports = mongoose.model('User', userSchema);


const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const UserSchema = new Schema({
  name: String, email: { type: String, unique: true, required: true }, password: String,
  balance: { type: Number, default: 0 }, referralCode: { type: String, unique: true },
  referredBy: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  machines: [{ type: Schema.Types.ObjectId, ref: 'Purchase' }], role: { type: String, default: 'user' }, createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('User', UserSchema);

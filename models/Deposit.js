
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const DepositSchema = new Schema({ user: { type: Schema.Types.ObjectId, ref: 'User', default: null }, amount: Number, tx_ref: String, status: String, type: { type: String, default: 'deposit' }, note: String, createdAt: { type: Date, default: Date.now }, completedAt: Date });
module.exports = mongoose.model('Deposit', DepositSchema);

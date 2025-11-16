
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const WithdrawSchema = new Schema({ user: { type: Schema.Types.ObjectId, ref: 'User' }, amount: Number, bank: String, accountNumber: String, accountName: String, status: String, createdAt: { type: Date, default: Date.now }, approvedAt: Date, adminNote: String });
module.exports = mongoose.model('Withdrawal', WithdrawSchema);

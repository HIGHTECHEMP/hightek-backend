
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const PurchaseSchema = new Schema({ user: { type: Schema.Types.ObjectId, ref: 'User' }, machine: { type: Schema.Types.ObjectId, ref: 'Machine' }, price: Number, startAt: Date, lastClaim: Date, active: { type: Boolean, default: true } });
module.exports = mongoose.model('Purchase', PurchaseSchema);

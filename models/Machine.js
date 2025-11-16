
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const MachineSchema = new Schema({ key: { type: String, unique: true }, name: String, price: Number, dailyPercent: Number });
module.exports = mongoose.model('Machine', MachineSchema);

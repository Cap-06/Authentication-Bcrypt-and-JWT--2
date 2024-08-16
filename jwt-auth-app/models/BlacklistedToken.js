const mongoose = require('mongoose');

const blacklistedTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
  },
  expirationDate: {
    type: Date,
    required: true,
  },
});

module.exports = mongoose.model('BlacklistedToken', blacklistedTokenSchema);

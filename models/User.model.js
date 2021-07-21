const { Schema, model } = require('mongoose');

const userSchema = new Schema(
  {
    username: {
      type: String,
      trim: true,
      required: [true, 'Username is required.'],
      unique: true
    },
    email: {
      type: String,
      required: [true, 'Email is required.'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Usa un email válido"],
    },
    passwordHash: {
      type: String,
      required: [true, "Password requerido"]
    }
  },
  {
    timestamps: true
  }
);

module.exports = model('User', userSchema);

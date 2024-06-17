import mongoose from "mongoose";

const User = mongoose.model('user', {
    name: String,
    email: String,
    password: String
});

export default User;
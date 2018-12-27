var mongoose = require('mongoose');
var crypto  = require('crypto');
var uniqueValidator = require('mongoose-unique-validator');
var jwt = require('jsonwebtoken');
var secret = require('../config').secret;

var UserSchema = new mongoose.Schema
(
    {
    username: {type: String, lowercase: true, unique: true, required: [true, "cant be blank"],
        match: [/^[a-zA-Z0-9]+$/, 'is invalid'], index: true},
    email: {type: String, lowercase: true, unique: true, required: [true, "can't be blank"],
        match: [/\S+@\S+\.\S+/, 'is invalid'], index: true},
    firstname: {type: String, unique: false, required: [true, "cant be blank"],
        match: [/^[a-z ,.'-]+$/i, 'is invalid'], index: true},
    lastname: {type: String, unique: false, required: [true, "cant be blank"],
        match: [/^[a-z ,.'-]+$/i, 'is invalid'], index: true},
    title: String,
    occupation: String,
    contactemail: String,
    contactphone: String,
    contactaddress: String,
    bio: String,
    image: String,
    hash: String,
    salt: String,
    // Todo: userPorts: [{type: mongoose.Schema.Types.ObjectId, ref: 'Port'}],
    // Todo: receivedPorts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Port' }],
    },
    {timestamps : true},
    {usePushEach : true}
);
// Password validation and creation
UserSchema.methods.setPassword = function(password){
    this.salt = crypto.randomBytes(16).toString('hex');
    this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
};

UserSchema.methods.validPassword = function(password) {
    var hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex');
    return this.hash === hash;
};

//Generating session tokens
UserSchema.methods.generateJWT = function(){

    var today = new Date();
    var exp = new Date(today);
    exp.setDate(today.getDate() + 60);

    return jwt.sign({
        id: this._id,
        username: this.username,
        exp: parseInt(exp.getTime() / 1000),
    }, secret);
};

//Json generateurs
UserSchema.methods.toAuthJSON = function(){
    return {
        username: this.username,
        email: this.email,
        firstname : this.firstname,
        lastname: this.lastname,
        token: this.generateJWT(),
        bio: this.bio,
        image: this.image || 'https://static.productionready.io/images/smiley-cyrus.jpg', 
    };
};

UserSchema.plugin(uniqueValidator, {message: 'Is already taken'});
var user = mongoose.model('User', UserSchema);

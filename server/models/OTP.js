const mongoose = require("mongoose");
const mailSender = require("../utils/mailSender");
const otpTemplate = require("../mail/templates/emailVerificationTemplate");

const OTPSchema = new mongoose.Schema({
    email:{
        type:String,
        required:true,
    },

    otp:{
        type:String,
        required:true,

    },

    createdAt: {
        type:Date,
        default:Date.now(),
        expires: 5*60, 
    }
});

// schema k baad and model se phele 

// a function -> to send emails

async function sendVerificationOTP(email, otp) {
    try {
        const mailResponse = await mailSender(email,
			"Verification Email",
			otpTemplate(otp))
        console.log("Email sent Successfully: ", mailResponse.response);
    } catch (error) {
        console.log("error occured while sending mails: ", error);
        throw error;
    }
}

OTPSchema.pre("save", async function (next) {
    console.log("Mail in pre hook", this.email)
    await sendVerificationOTP(this.email, this.otp);
    next();
}) 

module.exports = mongoose.model("OTP", OTPSchema);
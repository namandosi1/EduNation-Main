const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require("otp-generator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const Profile = require("../models/Profile");
const mailSender = require("../utils/mailSender");
const {passwordUpdated} = require("../mail/templates/passwordUpdate");

//sendOTP

exports.sendOtp = async(req,res) => {

    try{
        // fetch email from request ki body

    const {email} = req.body;

    // check if user already exist

    const existingUser = await User.findOne({email});

    // if user already exists, then return a response

    if(existingUser){
        return res.status(401).json({
            success:false,
            message:'User already registered',
        })
    }

        // generate otp

        var otp = otpGenerator.generate(6, {
            upperCaseAlphabets:false,
            lowerCaseAlphabets:false,
            specialChars:false,
        });
        console.log("OTP generated: ", otp);

        // check unique otp or not

        let result = await OTP.findOne({otp: otp});

        // agr nhi h unique otp
        while(result){
            otp = otpGenerator(6, {
                upperCaseAlphabets:false,
                lowerCaseAlphabets:false,
                specialChars:false,
            });
            result = await OTP.findOne({otp: otp});

        }

        const createdOtp = await OTP.create({
            email,
            otp
        })

        return res.status(200).json({
            success:true,
            message: "OTP created!",
            createdOtp
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:error.message,
        })
    }
}

// signup

exports.signUp = async (req,res) =>{

    try{
        // data fetch from request ki body
    const {
        firstName,
        lastName,
        email,
        password,
        confirmPassword,
        accountType,
        contactNumber,
        otp
    } = req.body;


    //validate krlo

    if(!firstName || !lastName || !email || !password || !confirmPassword
        || !otp){
            return res.status(403).json({
                success:false,
                message:"all fields are required",
            })
        }
    
    //2 password match krlo

     
        if(password !== confirmPassword){
            return res.status(400).json({
                success:false,
                message:"password match nhi ho rhe h recheck kro bhai"

            })
        }

    //check user already exist or not 

    const existingUser = await User.findOne({email});
    if(existingUser){
        return res.status(400).json({
            success:false,
            message:"user already registered",
        });
    }

    //find most recent otp stored for the user
    const recentOtp = await OTP.find({email}).sort({createdAt:-1}).limit(1);
    console.log(recentOtp);

    // validate otp
    if(recentOtp.length === 0){
        // otp not found 
        return res.status(400).json({
            success:false,
            message:'OTP not found',
        })
    }else if(otp !== recentOtp[0].otp){
        // invalid otp
        return res.status(400).json({
            success:false,
            message:"invalid otp"
        })
    }


    // hash password

    const hashedPassword = await bcrypt.hash(password,10);
    // create the user

    let approved = "";
    approved === "Instructor" ? (approved = false) : (approved = true);


    //entry the additional profile for the user

    const profileDetails = await Profile.create({
        gender:null,
        dateOfBirth:null,
        about:null,
        contactNumber:null,
    });

    const user = await User.create({
        firstName,
        lastName,
        email,
        contactNumber,
        password:hashedPassword,
        accountType,
        additionalDetails: profileDetails._id,
        image: `https://api.dicebear.com/8.x/initials/svg?seed=${firstName} ${lastName}`,
    })


    //return res

    return res.status(200).json({
        success:true,
        message:"user is registered successfully",
        user,
    });

    
    }

    catch(error){

        console.log(error);
        return res.status(500).json({
            success:false,
            message:"user cannot be registered. please try again ",
        })

    }
}


// login controller for authenticating users


exports.login = async (req,res) => {
    try{

        // get data from request body
        const {email, password} = req.body;


        // validation data

        if(!email || !password){
            res.status(400).json({
                success:false,
                message:'All fields are required, please try again'
            });
        }
        
        // user check exist or not 
        //In MongoDB, Population is the process of replacing the specified path in the document of one collection with the actual document from the other collection.
        const existinggUser = await User.findOne({email}).populate("additionalDetails").exec();
        if(!existinggUser){
            return res.status(400).json({
                success:false,
                message:"user is not registered please signup first",
            });
        }


        // generate JWT, after password matching
        //password match krne k liye = compare fn
        if(await bcrypt.compare(password, existinggUser.password)){
            const payload ={
                email : email,
                id : existinggUser._id,
                accountType: existinggUser.accountType,

            }
            const token = jwt.sign(payload, process.env.JWT_SECRET, {
                expiresIn:"24h",
            });
            existinggUser.toObject();

            existinggUser.token = token;

            existinggUser.password= undefined;

            // create cookie and send response 
            const options = {
                expires: new Date(Date.now() + 3*24*60*60*1000),
                httpOnly:true
            }

            return res.cookie("token", token , options).status(200).json({
                success:true,
                token,
                existinggUser,
                message:'logged in Successfully '
            })


        }

        else{
            return res.status(401).json({
                success:false,
                message:'Password is incorrect'
            }) 
        }
        
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Login failure Please try again",
        });

    }
};





// change password

exports.changePassword = async (req, res) => {
	try {
		// Get user data from req.user
		const userDetails = await User.findById(req.user.id);

		// Get old password, new password, and confirm new password from req.body
		const { oldPassword, newPassword } = req.body;

		// Validate old password
		const isPasswordMatch = await bcrypt.compare(
			oldPassword,
			userDetails.password
		);
		if (!isPasswordMatch) {
			// If old password does not match, return a 401 (Unauthorized) error
			return res
				.status(401)
				.json({ success: false, message: "The password is incorrect" });
		}

		// Match new password and confirm new password
		// if (newPassword !== confirmNewPassword) {
		// 	// If new password and confirm new password do not match, return a 400 (Bad Request) error
		// 	return res.status(400).json({
		// 		success: false,
		// 		message: "The password and confirm password does not match",
		// 	});
		// }

		// Update password
		const encryptedPassword = await bcrypt.hash(newPassword, 10);
		const updatedUserDetails = await User.findByIdAndUpdate(
			req.user.id,
			{ password: encryptedPassword },
			{ new: true }
		);

		// Send notification email
		try {
			const emailResponse = await mailSender(
				updatedUserDetails.email,
				passwordUpdated(
					updatedUserDetails.email,
					`Password updated successfully for ${updatedUserDetails.firstName} ${updatedUserDetails.lastName}`
				)
			);
			console.log("Email sent successfully:", emailResponse.response);
		} catch (error) {
			// If there's an error sending the email, log the error and return a 500 (Internal Server Error) error
			console.error("Error occurred while sending email:", error);
			return res.status(500).json({
				success: false,
				message: "Error occurred while sending email",
				error: error.message,
			});
		}

		// Return success response
		return res
			.status(200)
			.json({ success: true, message: "Password updated successfully" });
	} catch (error) {
		// If there's an error updating the password, log the error and return a 500 (Internal Server Error) error
		console.error("Error occurred while updating password:", error);
		return res.status(500).json({
			success: false,
			message: "Error occurred while updating password",
			error: error.message,
		});
	}
};



const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");
const crypto = require('crypto')



//resetpasswordtoken

exports.resetPasswordToken = async(req,res) =>{
  try{
      // get email from req body
      const {email}= req.body;

      // check user for this email, email validation

      if(!email){
        return res.status(400).json({
            success:false,
            message:"Email is empty"
        })
    }

  
      const existingUser = await User.findOne({email:email});
  
      if(!existingUser){
          return res.json({
              success:false,
              message:'your email is not registered with us '
          })
      }
  
      // generate token
      const token = crypto.randomUUID()

         // update user by adding token and expiration time
  
   
      const updatedUser = await User.findOneAndUpdate({email},
                                                   {
                                                   token:token,
                                                   resetPasswordExpires: Date.now() + 5*60*1000
                                                   },
                                                   {new:true})


      // create url
      const url = `http://localhost:3000/update-password/${token}`



      // send mail containing the url
      await mailSender(email, "Password Reset Link", `Password reset link: ${url}`);


      // return response 
      return res.status(200).json({
          success:true,
          message:'Reset link sent'
      })
  } catch (error) {
       console.log(error);
       return res.status(500).json({
           success:false,
           message:'Something went wrong while sending reset pwd mail'
       })
  }
}
      




//resetpassword

exports.resetPassword = async (req, res) =>{
   try{
     // data fetch

    // frontend n url se body m fek diya token ko isiliye fetch kr rhe h 
    const {password, confirmPassword, token} = req.body;

    // validation
    if(password != confirmPassword){
        return res.json({
            success:false,
            messsage:'password not matching'
        });
    }

    // get userdetails from db using token

    const userDetails = await User.findOne({token: token});

    // if no entry - invalid token
    if(!userDetails){
        res.json({
            success:false,
            message:'token invalid',
        });
    }

    // token time check

    if(userDetails.resetPasswordExpires < Date.now()){
        return res.status(500).json({
            success:false,
            message:'token is expired plzz regenerate your token',
        })

    }

    if (password!==confirmPassword) {
        return res.status(500).json({
            success:false,
            message:"Password Don't match"
        })
    }


    // hash password

    const encryptedPassword = await bcrypt.hash(password,10);

    // update password
    await User.findOneAndUpdate(
        {token:token},
        {password:encryptedPassword},
        {new:true },
    );

    // return response

    return res.status(200).json({
        success:true,
        message:'Password reset successful',
    })

   }
   catch(error){

    console.log(error);
    res.status(500).json({
        success:false,
        message:'error aagya babuu',
    })

   }
}


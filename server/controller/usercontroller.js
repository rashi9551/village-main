const userModel = require("../model/user")
const otpModel = require("../model/user_otpmodel")
const otpgenerator=require("otp-generator")
const nodemailer=require("nodemailer")

const bcrypt= require("bcrypt")


const 
    {
        nameValid,
        emailValid,
        phoneValid,
        confirmpasswordValid,
        passwordValid
    }=require("../../utils/validators/usersignupvalidators")
    const { Email,pass} = require('../../.env');


const generateotp=()=>{
    const otp = otpgenerator.generate(6, { upperCaseAlphabets: false,lowerCaseAlphabets:false, specialChars: false,digits:true });
console.log('Generated OTP:', otp);
return otp;
}
const sendmail = async (email, otp) => {
    try {
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: Email,
                pass: pass
            }
        });

        var mailOptions = {
            from: 'Village<thefurnify@gmail.com>',
            to: email,
            subject: 'E-Mail Verification',
            text: 'Your OTP is:' + otp
        };

        transporter.sendMail(mailOptions);
        console.log("E-mail sent sucessfully");

    }
    catch (err) {
        console.log("error in sending mail:", err);
    }
}

const index=async (req,res)=>{
await res.render("index")

}

const signin=async (req,res)=>{
    await res.render("signin")
}

const signup=async (req,res)=>{
    await res.render("signup")
}
const signotp=async (req,res)=>{
    try
    {
        const username = req.body.username
        const email = req.body.email
        const phone = req.body.phone
        const password = req.body.password
        const cpassword = req.body.confirm_password

        const isusernameValid = nameValid(username)
        const isEmailValid = emailValid(email)
        const isPhoneValid = phoneValid(phone)
        const ispasswordValid = passwordValid(password)
        const iscpasswordValid = confirmpasswordValid(cpassword, password)

        const emailExist = await userModel.findOne({ email: email })
        if (emailExist) {
            res.render('signup', { emailerror: "E-mail already exits" })
        }
        else if (!isusernameValid) {
            res.render('signup', { nameerror: "Enter a valid Name" })
        }
        else if (!isEmailValid) {
            res.render('signup', { emailerror: "Enter a valid E-mail"})
        }
        else if (!isPhoneValid) {
            res.render('signup', { phoneerror: "Enter a valid Phone Number" })
        }
        else if (!ispasswordValid) {
            res.render('signup', { passworderror: "Password should contain one(A,a,2)" })
        }
        else if (!iscpasswordValid) {
            res.render('signup', { cpassworderror: "Password and Confirm password should be match" })
        }
        else 
        {
            const hashedpassword = await bcrypt.hash(password, 10)
            const user=new userModel({username:username, email: email, phone: phone, password: hashedpassword })
            req.session.user = user
            req.session.signup = true
            req.session.forgot = false

            const otp = generateotp()
            console.log(otp);
            const currentTimestamp = Date.now();
            const expiryTimestamp = currentTimestamp + 30 * 1000;
            const filter = { email: email };
            const update = 
            {
                            $set:
                            {
                                email: email,
                                otp: otp,
                                expiry: new Date(expiryTimestamp),
                            }
            };

            const options = { upsert: true };

            await otpModel.updateOne(filter, update, options);
            await sendmail(email, otp)
            res.redirect('/otp')
        }
    }
    catch (err) 
    {
        console.error('Error:', err);
        res.send('error')
    }
}
const otp = async (req, res) => {
    try {
        res.render('otp')
    }
    catch {
        res.status(200).send('error occured')

    }

}
const verifyotp=async(req,res)=>{
    try{
        const enteredotp=req.body.otp
        const user=req.session.user
        console.log(enteredotp);
        console.log(req.session.user);
        const email = req.session.user.email
        const userdb = await otpModel.findOne({ email: email })
        const otp = userdb.otp
        const expiry = userdb.expiry
        console.log(otp);
        if(enteredotp == otp ){
            user.isVerified=true;
            try{
                if(req.session.signup)
                {
                    await userModel.create(user)
                    res.redirect("/")
                }

            }
            catch(error){
                console.error(error);
                res.status(500).send('Error occurred while saving user data');

            }
        }
        else{
            res.status(400).send("Wrong OTP or Time Expired");

        }


    }
    catch(error){
        console.log(err);
        res.status(500).send('error occured')

    }
}
const resendotp=async(req,res)=>{
    try{
        const email=req.session.user.email
        const otp=generateotp()
        console.log(otp);


        const currentTimestamp = Date.now();
        const expiryTimestamp = currentTimestamp + 60 * 1000;
        await otpModel.updateOne({ email: email },{otp:otp,expiry:new Date(expiryTimestamp)})
        await sendmail(email, otp)
        
    }
    catch(err){
        console.log(err);

    }
}
const login=async (req,res)=>{
    try {
        const email = req.body.email;
        const user = await userModel.findOne({ email: email });

        // Check if the user exists
        if (!user) {
            throw new Error('User not found');
        }

        const passwordmatch = await bcrypt.compare(req.body.password, user.password);

        if (passwordmatch ) {
            // Authentication successful
            req.session.userId = user._id;
            req.session.username = user.username;
            req.session.isAuth = true;
            res.redirect('/');
        } else {
            // Authentication failed
            res.render("signin",{passworderror:"incorrect password"});
        }
    } catch (error) {
        // Error occurred, could be due to user not found or other issues
        res.render("signin",{username:"incorrect username"});
    }

}



module.exports={index,
    signin,
    signup,
    signotp,
    login,
    otp,
    verifyotp,
    resendotp
}

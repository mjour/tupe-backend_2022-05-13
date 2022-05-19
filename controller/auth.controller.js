const con = require("../config/db.config");
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
var path = require('path');
const fs = require("fs");
const handlebars = require("handlebars");
const twilio = require('twilio');

exports.registerUser = (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var phone = req.body.phone;
    var password = req.body.password;
    var confirmPassword = req.body.confirmPassword;
    var registrationType = req.body.registrationType;
    const token = registrationType ? req.body.scode : req.body.vcode;
    const emailVerificationQuery = 'SELECT * FROM email_verification WHERE email = ? ORDER BY created_at DESC';
    const smsVerificationQuery = 'SELECT * FROM phone_verification WHERE phone = ? ORDER BY created_at DESC';
    const query = registrationType ? smsVerificationQuery : emailVerificationQuery;
    const queryParameter = registrationType ? [phone] : [email];

    con.query(query, [ queryParameter ], function(error, verificationAttempts) {
        if (error) {
            res.json({
                response: false,
                message: 'Something went wrong. Please try again.',
                statusCode: 500
            })
        } else {
            if (verificationAttempts.length > 0) {
                const latestToken = verificationAttempts[0].token
                if (latestToken === token) {
                    if (!name) {
                        res.json({ response: false, message: "Referrer is required.", statusCode: 500 })
                    } else if (!email && registrationType == 0) {
                        res.json({ response: false, message: "Email address is required.", statusCode: 500 })
                    } else if (!password) {
                        res.json({ response: false, message: "Password is required.", statusCode: 500 })
                    } else if (!confirmPassword) {
                        res.json({ response: false, message: "Confirm password is required.", statusCode: 500 })
                    } else if (req.body.password != req.body.confirmPassword) {
                        res.json({ response: false, message: "Password and confirm password does not match!", statusCode: 500 })
                    } 
                    else if (req.body.citizenship == false) {
                        res.json({ response: false, message: "Terms and conditions are required.", statusCode: 500 })
                    } 
                    else if (registrationType != 1 && registrationType != 0) {
                        res.json({ response: false, message: "Registration type {email or phone} is required.", statusCode: 500 })
                    } else {
                        con.query('SELECT * FROM users WHERE email = ? and registration_type = "email"', [email], function (err, user) {
                            if (user != "") {
                                res.json({ response: false, message: 'Email address is already exist!', statusCode: 500 });
                            } else {
                                if (password) {
                                    if (password == confirmPassword) {
                                        bcrypt.hash(req.body.password, 10, (error, hash) => {
                                            if (error) {
                                                res.json({ response: false, message: 'Error while password bcrypting!', error: error, statusCode: 500 });
                                            } else {
                                                var today = new Date();
                                                if(registrationType == 0){
                                                    registrationType = 'email'
                                                } else {
                                                    registrationType = 'phone' 
                                                }
                
                                                var user_details = {
                                                    "name": name,
                                                    "email": email,
                                                    "phone": phone,
                                                    "registration_type": registrationType,
                                                    "password": hash,
                                                    "created_at": today,
                                                    "updated_at": today,
                                                }
                
                                                con.query('INSERT INTO users SET ?', user_details, function (error, results, fields) {
                                                    if (error) {
                                                        res.json({ response: false, message: 'Error while inserting user!' });
                                                    } else {
                                                        res.json({ response: true, data: results, message: 'Your registration has been done successfully!' });
                                                    }
                                                });
                                            }
                                        });
                                    } else {
                                        res.json({ response: false, message: 'Password does not match!' });
                                    }
                                } else {
                                    res.json({ response: false, message: 'Password is empty' });
                                }
                            }
                        });
                    }
                } else {
                    res.json({
                        response: false,
                        message: 'Token does not match',
                        statusCode: 500
                    })
                }
            } else {
                res.json({
                    response: false,
                    message: 'Token does not match',
                    statusCode: 500
                })
            }
        }
    })
}

exports.loginUser = (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    var phone = req.body.phone;

    if (!req.body.password) {
        res.json({ response: false, message: "Please enter password", statusCode: 500 })
    } else {
        if (email) {
            con.query('SELECT * FROM users WHERE email = ? and registration_type = "email"', [email], function (err, user) {
                if (err) {
                    res.json({
                        response: false,
                        message: 'there are some error with query'
                    })
                } else {
                    if (user != "") {
                        bcrypt.compare(password, user[0].password)
                            .then((match) => {
                                if (match) {
                                    const payload = { email: user[0].email, id: user[0].id, role: user[0].role };
                                    const options = { expiresIn: 60 * 60 };
                                    const secret = "loginJWTTokenBaseVerification";
                                    const token = jwt.sign(payload, secret, options);
    
                                    const userData = {
                                        id: user[0].id,
                                        name: user[0].name,
                                        email: user[0].email,
                                        token: token,
                                    }
    
                                    res.json({ response: true, message: 'Login Successfully!!!', data: userData, statusCode: 200 });
                                } else {
                                    res.json({ response: false, message: 'password is invalid', error: err, statusCode: 500 });
                                }
                            }).catch((err) => {
                                res.json({ response: false, message: 'something went wrong.', error: err, statusCode: 500 });
                            });
                    } else {
                        res.json({ response: false, message: 'email is invalid', statusCode: 401 });
                    }
                }
            })
        } else if(phone) {
            con.query('SELECT * FROM users WHERE phone = ? and registration_type = "phone"', [phone], function (err, user) {
                if (err) {
                    res.json({
                        response: false,
                        message: 'there are some error with query'
                    })
                } else {
                    if (user != "") {
                        bcrypt.compare(password, user[0].password)
                            .then((match) => {
                                if (match) {
                                    const payload = { email: user[0].phone, id: user[0].id, role: user[0].role };
                                    const options = { expiresIn: 60 * 60 };
                                    const secret = "loginJWTTokenBaseVerification";
                                    const token = jwt.sign(payload, secret, options);
                                    const userData = {
                                        id: user[0].id,
                                        name: user[0].name,
                                        phone: user[0].phone,
                                        token: token,
                                    }
                                    res.json({ response: true, message: 'Login Successfully!!!', data: userData, statusCode: 200 });
                                } else {
                                    res.json({ response: false, message: 'password is invalid', error: err, statusCode: 500 });
                                }
                            }).catch((err) => {
                                res.json({ response: false, message: 'something went wrong.', error: err, statusCode: 500 });
                            });
                    } else {
                        res.json({ response: false, message: 'Phone number is invalid', statusCode: 401 });
                    }
                }
            })
        } else {
            res.json({ response: false, message: 'Please enter valid Credentials', statusCode: 401 });
        }
    }
}

exports.forPassWithPhone = (req, res) => {
    var phone = req.body.phone;
    var email = req.body.email;
    var rand = Math.floor(100000 + Math.random() * 900000);
   
    if (phone) {
        con.query('SELECT * FROM users WHERE phone = ?', [phone], function (err, user) {
            if (user != "") {
                
                const accountSid = 'AC746439d27c7e749f873d7b6034a66a2c'; 
                const authToken = '0ee1fb898f9fec9a913357829044a21b';
            
                const client = new twilio(accountSid, authToken);
            
                client.messages
                .create({
                body: `${rand} is your Tupe code`,
                to: `${phone}`, // Text this number
                from: '+18597626756', // From a valid Twilio number
                })
                .then((message) => {
                    res.json({ response: true, message: 'sucessfully send SMS verification code', statusCode: 200, code: rand });
                })
                .catch((err) => {
                    res.json({ response: false, message: 'something went wrong when send SMS verification code.', error: err, statusCode: 500 });
                })
            } else {
                res.json({ response: false, message: 'Invalid Phone.', statusCode: 500 });
            }
        });
    } else if(email) {
        // let transporter = nodemailer.createTransport({
        //     service: "gmail",
        //     port : 465,
        //     secure: false,
        //     auth: {
        //         user:"node.vpnin@gmail.com",
        //         pass:"ioqvjfxnhgygrvzo"
        //     },
        // });
        let transporter = nodemailer.createTransport({
            name: 'attractfreeclicks.com',
            host: 'uscentral48.myserverhosts.com',
            post: 465,
            secure: true,
            auth: {
                user: 'testonly@attractfreeclicks.com',
                pass: 'k2Z4zPK*&W99)Glk',
            },
            tls: {
                // do not fail on invalid certs
                rejectUnauthorized: false,
            }
        })
        var emailCode = path.join(__dirname, '../views/email-code.ejs')
        fs.readFile(emailCode, { encoding: 'utf-8' }, (err, ejs) => {
            if (err) {
                res.json({ response: false, message: 'something went wrong when send Email verification code.', error: err, statusCode: 500 });
            } else {
                var template = handlebars.compile(ejs);
                var replacements = {
                    email: email,
                    code: rand
                }
    
                var replaceToEjs = template(replacements);
    
                transporter.sendMail({
                    from:'node.vpnin@gmail.com',  
                    to: email,
                    subject: 'Forgot Password',
                    html: replaceToEjs
                }, (error, info) => {
                    if (error) {
                        res.json({ response: false, message: 'something went wrong when send Email verification code.', error: error, statusCode: 500 });
                    } else {
                        res.json({ response: true, message: 'sucessfully send email verification code', statusCode: 200, code: replacements.code });
                    }
                });
    
            }
        });
    } else {
        res.json({ response: false, message: "Please enter valid Credentials", statusCode: 500 })
    }
}

exports.resPassWithPhone = (req, res) => {
    const password = req.body.password;
    const phone = req.body.phone;
    const email = req.body.email;

    if (!password) {
        res.json({ response: false, message: "Please enter a password", statusCode: 500 })
    } else {
        bcrypt.hash(password, 10, (error, hash) => {
            if (error) {
                res.json({ response: false, message: 'something went wrong when Reset Password & convert hash password.', error: error, statusCode: 500 });
            } else {
                const updateData = {
                    password: hash,
                };
                con.query('SELECT * FROM users WHERE phone = ? OR email = ?', [phone,email], function (err, user) {
                    if (user != "") {
                        con.query('update users set ? where phone = ? OR email = ?', [updateData, phone, email], function (err, response) {
                            res.json({ response: true, message: 'Successfully Reset Password.', statusCode: 200 });
                        })
                    } else {
                        res.json({ response: false, message: 'something went wrong when Reset Password & Find And Update User', statusCode: 500 });
                    }
                })
            }
        })
    }
}

exports.sendCode = (req, res) => {
    const email = req.body.email
    const token = Math.floor(100000 + Math.random() * 900000);

    const emailRegistration = {
        "email": email,
        "token": token,
        "created_at": new Date()
    };

    con.query('INSERT INTO email_verification SET ?', emailRegistration, function (error, results, fields) {
        if (error) {
            res.json({
                response: false,
                message: 'Something went wrong. Please try again.',
                statusCode: 500
            })
        } else {
            // let transporter = nodemailer.createTransport({
            //     service: "gmail",
            //     port : 465,
            //     secure: false,
            //     auth: {
            //         user:"node.vpnin@gmail.com",
            //         pass:"ioqvjfxnhgygrvzo"
            //     },
            // });

            let transporter = nodemailer.createTransport({
                name: 'attractfreeclicks.com',
                host: 'uscentral48.myserverhosts.com',
                post: 465,
                secure: true,
                auth: {
                    user: 'testonly@attractfreeclicks.com',
                    pass: 'k2Z4zPK*&W99)Glk',
                },
                tls: {
                    // do not fail on invalid certs
                    rejectUnauthorized: false,
                }
            })

            var emailCode = path.join(__dirname, '../views/email-code.ejs')
            fs.readFile(emailCode, { encoding: 'utf-8' }, (err, ejs) => {
                if (err) {
                    res.json({ response: false, message: 'something went wrong when send Email verification code.', error: err, statusCode: 500 });
                } else {
                    var template = handlebars.compile(ejs);
                    var replacements = {
                        email: email,
                        code: token
                    }

                    var replaceToEjs = template(replacements);

                    transporter.sendMail({
                        from:'testonly@attractfreeclicks.com',  
                        to: email,
                        subject: 'Verify Email Address for Tupe',
                        html: replaceToEjs
                    }, (error, info) => {
                        if (error) {
                            res.json({ response: false, message: 'something went wrong when send Email verification code.', error: error, statusCode: 500 });
                        } else {
                            res.json({ response: true, message: 'sucessfully send email verification code', statusCode: 200});
                        }
                    });

                }
            });
        }
    })
}

exports.sendSmsCode = (req, res) => {
    var phone = req.body.phone;
    
    const accountSid = 'AC746439d27c7e749f873d7b6034a66a2c'; 
    const authToken = '0ee1fb898f9fec9a913357829044a21b';

    const client = new twilio(accountSid, authToken);
    var token = Math.floor(100000 + Math.random() * 900000);

    const phoneRegistration = {
        "phone": phone,
        "token": token,
        "created_at": new Date()
    };

    con.query('INSERT INTO phone_verification SET ?', phoneRegistration, function(error, results, fields) {
        if (error) {
            res.json({
                response: false,
                message: 'Something went wrong. Please try again.',
                statusCode: 500
            })
        } else {
            client.messages
                .create({
                    body: `Your Tupe registration verification code is : ${token}`,
                    to: `${phone}`, // Text this number
                    from: '+18597626756', // From a valid Twilio number
                })
                .then((message) => {
                    res.json({ response: true, message: 'sucessfully send SMS verification code', statusCode: 200, code: token });
                })
                .catch((err) => {
                    res.json({ response: false, message: 'something went wrong when send SMS verification code.', error: err, statusCode: 500 });
                })
        }
    })
}


// Unused API
exports.forgotPassword = (req, res) => {
    var email = req.body.email;

    if (!req.body.email) {
        res.json({ response: false, message: "Please enter email", statusCode: 500 })
    } else {
        con.query('SELECT * FROM users WHERE email = ?', [email], function (err, user) {
            if (user != "") {
                const payload = { email: user[0].email, id: user[0].id }
                const options = { expiresIn: 60 * 60 }
                const secret = "forgotPasswordJWTTokenBaseVerification";

                const token = jwt.sign(payload, secret, options);

                // let transporter = nodemailer.createTransport({
                //     service: "gmail",
                //     port: 465,
                //     secure: false,
                //     auth: {
                //         user: "node.vpnin@gmail.com",
                //         pass: "ioqvjfxnhgygrvzo",
                //     },
                // });

                let transporter = nodemailer.createTransport({
                    name: 'attractfreeclicks.com',
                    host: 'uscentral48.myserverhosts.com',
                    post: 465,
                    secure: true,
                    auth: {
                        user: 'testonly@attractfreeclicks.com',
                        pass: 'k2Z4zPK*&W99)Glk',
                    },
                    tls: {
                        // do not fail on invalid certs
                        rejectUnauthorized: false,
                    }
                })
                
                var ForgotPasswordPath = path.join(__dirname, '../views/forgot-password-link.ejs')
                fs.readFile(ForgotPasswordPath, { encoding: 'utf-8' }, (err, ejs) => {
                    if (err) {
                        res.json({ response: false, message: 'something went wrong when Forgot Password & Find Path.', error: err, statusCode: 500 });
                    } else {
                        var template = handlebars.compile(ejs);
                        var replacements = {
                            name: user[0].userName,
                            email: email,
                            link: "http://localhost:3000" + "/reset-password/" + token + "/" + email
                        }

                        var replaceToEjs = template(replacements);

                        transporter.sendMail({
                            from: 'node.vpnin@gmail.com',
                            to: email,
                            subject: 'Forgot Password',
                            html: replaceToEjs
                        }, (error, info) => {
                            if (error) {
                                res.json({ response: false, message: 'something went wrong when Forgot Password & Send Mail.', error: error, statusCode: 500 });
                            } else {
                                res.json({ response: true, message: 'sucessfully send link for change password', statusCode: 200 });
                            }
                        });

                    }
                });
            } else {
                res.json({ response: false, message: 'Invalid Email.', statusCode: 500 });
            }
        });
    }
}

// Unused API
exports.resetPassword = (req, res) => {
    const token = req.body.token;
    const email = req.body.email;
    const password = req.body.password;
    const conformPassword = req.body.conformPassword;

    if (!req.body.token) {
        res.json({ response: false, message: "Please send valid token", statusCode: 500 })
    } else if (!req.body.email) {
        res.json({ response: false, message: "Please enter email", statusCode: 500 })
    } else if (!req.body.password) {
        res.json({ response: false, message: "Please enter password", statusCode: 500 })
    } else if (!req.body.conformPassword) {
        res.json({ response: false, message: "Please enter confirmPassword", statusCode: 500 })
    } else if (req.body.password != req.body.conformPassword) {
        res.json({ response: false, message: "Password and confirm password didn't match.", statusCode: 500 })
    } else {
        const options = {
            expiresIn: 60 * 60
        };

        try {
            var decoded = jwt.verify(token, 'forgotPasswordJWTTokenBaseVerification', options);

            if (email === decoded.email) {
                if (password === conformPassword) {
                    bcrypt.hash(password, 10, (error, hash) => {
                        if (error) {
                            res.json({ response: false, message: 'something went wrong when Reset Password & convert hash password.', error: error, statusCode: 500 });
                        } else {
                            const updateData = {
                                password: hash,
                            };
                            con.query('SELECT * FROM users WHERE email = ?', [email], function (err, user) {
                                if (user != "") {
                                    con.query('update users set ? where email = ?', [updateData, email], function (err, response) {
                                        res.json({ response: true, message: 'Successfully Reset Password.', statusCode: 200 });
                                    })
                                } else {
                                    res.json({ response: false, message: 'something went wrong when Reset Password & Find And Update User', statusCode: 500 });
                                }
                            })
                        }
                    });
                } else {
                    res.json({ response: false, message: 'conform-password And password is not match', statusCode: 500 });
                }
            } else {
                res.json({ response: false, message: 'Email address is invalid', statusCode: 500 });
            }

        } catch (err) {
            res.json({ response: false, message: 'Authentication error ', error: err, statusCode: 500 });
        }
    }
}
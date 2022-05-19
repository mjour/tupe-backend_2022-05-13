const { param, body, validationResult } = require('express-validator')

exports.userValidation = () => {
  return [
    body('name').notEmpty().withMessage('Referrer is required!'),
    body('password').notEmpty().withMessage('Password is required!'),
    body('confirmPassword').notEmpty().withMessage('Confirm Password is required!'),
  ]
}
exports.validateUserToken = () => {
  return [
    body('token').notEmpty().withMessage('Token is required!')
  ]
}

exports.authLogin = () => {
  return [
    body('email').notEmpty().withMessage('Email is required!'),
    body('password').notEmpty().withMessage('Password is required!'),
  ]
}


exports.forgotPassword = () => {
  return [
    body('email').notEmpty().withMessage('Email is required!'),
  ]
}

exports.validate = (req, res, next) => {
    const errors = validationResult(req)
    
    if (errors.isEmpty()) {
      return next()
    }
    const extractedErrors = []
    errors.array().map(err => extractedErrors.push({ [err.param]: err.msg }))
  
    return res.status(422).json({
      errors: extractedErrors,
    })
}





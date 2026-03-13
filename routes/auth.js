var express = require('express');
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, handleResultValidator, ChangePasswordValidator } = require('../utils/validatorHandler')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let {checkLogin} = require('../utils/authHandler')
let fs = require('fs')
let path = require('path')
/* GET home page. */
router.post('/register', RegisterValidator, handleResultValidator, async function (req, res, next) {
    let newUser = userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69aa8360450df994c1ce6c4c"
    );
    await newUser.save()
    res.send({
        message: "dang ki thanh cong"
    })
});
router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let getUser = await userController.FindByUsername(username);
    if (!getUser) {
        res.status(403).send("tai khoan khong ton tai")
    } else {
        if (getUser.lockTime && getUser.lockTime > Date.now()) {
            res.status(403).send("tai khoan dang bi ban");
            return;
        }
        if (bcrypt.compareSync(password, getUser.password)) {
            await userController.SuccessLogin(getUser);
            let privateKey = fs.readFileSync(path.join(__dirname, '../private_key.pem'), 'utf8')
            let token = jwt.sign({
                id: getUser._id
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn:'30d'
            })
            res.send(token)
        } else {
            await userController.FailLogin(getUser);
            res.status(403).send("thong tin dang nhap khong dung")
        }
    }

});
router.get('/me',checkLogin,function(req,res,next){
    res.send(req.user)
})

router.post('/changepassword', checkLogin, ChangePasswordValidator, handleResultValidator, async function (req, res, next) {
    let { oldpassword, newpassword } = req.body;
    let user = req.user; // assigned in checkLogin middleware
    if (bcrypt.compareSync(oldpassword, user.password)) {
        user.password = newpassword;
        await user.save();
        res.send({
            message: "Doi mat khau thanh cong"
        })
    } else {
        res.status(400).send("Mat khau cu khong chinh xac");
    }
});
module.exports = router;

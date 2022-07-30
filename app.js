const bodyParser = require('body-parser')
const express=require('express')
const router = express.Router()
const app=express()
const mongoose=require('mongoose')
const User=require('./model/user')
const bcrypt=require('bcryptjs')
const jwt = require('jsonwebtoken')


const JWT_SECRET='thisisthesecrettoken123456#*-%@'


mongoose.connect('mongodb://localhost:27017/login-app-db',{
    useNewUrlParser:true,
    useUnifiedTopology:true,
   
})


const port =3000

app.use(express.static('public'))


app.use(bodyParser.json())

app.post('/api/register',async(req,res)=>{
    const {email,username, password:plainTextPassword}=req.body
    //username validity test 
    if(!username || typeof username !=='string') {
         return res.json({status:'error', error:'Invalid username'})
     }
    //password validity   
    if(!plainTextPassword || typeof plainTextPassword !=='string') {
        return res.json({status:'error', error:'Invalid password'})
    } 
    //password length
    if(plainTextPassword.length<5){
        return res.json({ status:'error', error:'password should be atleast 6 characters'})
    }

    const password=await bcrypt.hash(plainTextPassword,5)

    try{

    const response=await User.create({
        email,
        username,
        password
    })
    console.log('user created suceessfully: ',response)
    
 

    }catch(error){

        if(error.code===11000){
        return res.json({status:'error',error:'username or already in use'})
        }throw error
    }

    res.json({status:'ok'})
})

app.post('/api/signin',async(req,res)=>{

    const{username, password}=req.body

    //find command on the data base
    const user =await User.findOne({ username}).lean()
    if(!user){
        return res.json({status: 'error', error: 'invalid username/password'})
    }

    if ( await bcrypt.compare(password, user.password)){
        //username and password successfull
        const token = jwt.sign({id:user._id, username: user.username}, JWT_SECRET)

        return res.json({status: 'ok', data: token}) 
        
    
    }

    res.json({status: 'error', error: 'invalid username/password'})
})

app.use('/api/verify', (req, res, next)=> {
    const{ token } = req.body
    const user = jwt.verify(token, JWT_SECRET)

    res.redirect("./public/calculator.html",301)
    next();
})

app.listen(port, ()=>{
    console.log('server is listening on port '+port)
})

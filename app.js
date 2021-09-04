const express = require('express')
const expressLayouts = require('express-ejs-layouts')
const mongoose = require('mongoose')
const faker = require('faker')


const jwt = require('jsonwebtoken')
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt')
const { nanoid } = require('nanoid')
const nodemailer = require('nodemailer');
// Mailer transport
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'fajaradiputra127@gmail.com',
        pass: '07511766d197e02df7c00d6938e38d97'
    }
});
// End of Mailer transport


// Flash Message npm
const session = require('express-session')
const cookieParser = require('cookie-parser')
const flash = require('connect-flash')
// Flash Message npm


faker.locale = 'id_ID'
const Schema = mongoose.Schema
const app = express()
const csvWriter = require('csv-write-stream');
const fs = require('fs');
const { decode } = require('punycode')
const writer = csvWriter();
writer.pipe(fs.createWriteStream('queries.csv'));

mongoose.set('debug', function (collection, method, query, doc) {
    writer.write({
        collection: collection,
        method: method,
        query: query,
        doc: JSON.stringify(doc)
    });
});

// close stream on mongoose disconnected
mongoose.connection.on('disconnected', function () {
    writer.end();
});
mongoose.connect('mongodb+srv://admin:admin@cluster0.qcdex.mongodb.net/simple-blog?retryWrites=true&w=majority', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
})
const PostSchema = new Schema({
    title: String,
    created: {
        type: Number,
        default: new Date().getTime()
    },
    excerpt: String,
    body: String,
    slug: {
        type: String,
        unique: true,
        dropDups: true,
        required: true
    },
    categorie: {
        type: Schema.Types.ObjectId,
        ref: 'Categorie',
        required: true
    },
    author: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    published: {
        type: Number,
        default: new Date().getTime()
    },
})
const AuthorSchema = new Schema({
    name: String,
    email: String,
    password: String
})
const CategorieSchema = new Schema({
    name: {
        type: String,
        unique: true,
        dropDups: true
    },
    slug: {
        type: String,
        unique: true,
        dropDups: true
    },
    posts: [{
        type: Schema.Types.ObjectId,
        ref: 'Post'
    }]
})
const UserSchema = new Schema({
    name: {
        type: String,
        unique: true,
        dropDups: true
    },
    email: {
        type: String,
        unique: true,
        dropDups: true
    },
    password: String,
    isActive: {
        type: Boolean,
        default: false
    }
})
const TokenSchema = new Schema({
    token: String,
    email: String,
    type: String
})
const Author = mongoose.model('Author', AuthorSchema)
const Post = mongoose.model('Post', PostSchema)
const Categorie = mongoose.model('Categorie', CategorieSchema)
const User = mongoose.model('User', UserSchema)
const Token = mongoose.model('Token',TokenSchema)
app.use(expressLayouts)
app.use(express.static('assets'))
app.use(express.urlencoded({extended: true}))
app.set('view engine', 'ejs')
app.set('layout', 'main')
app.use(cookieParser('secret'))
app.use(session({cookie: {},secret: 'secret',resave: true,saveUninitialized: true }))
app.use(flash())
app.use((req,res,next) => {
    const token = req.cookies.access_token;
    if(!token){
        return next()
    }
    jwt.verify(token,'secret',(err,decode) => {
        if(err){
            res.clearCookie('access_token')
            return next()
        }
        res.locals = {login: true, username: decode.data.name}
        next()
    })
})
// Auth
app.post('/register',[body('username').isLength({min: 4}).withMessage('This field required at least 4 chars').trim().custom(async value => {
    const user = await User.findOne({name: value})
    if(user){
        return Promise.reject('Username already in use')
    }
}),body('password').isLength({min: 5}).withMessage('This field required at least 5 chars').trim().custom((value,{req}) => {
    if(value != req.body.password2){
        return Promise.reject('Password not match')
    }
    return true
}),body('email').isLength({min: 1}).withMessage('This field is required').isEmail().withMessage('Insert a valid email').custom(async value => {
    const user = await User.findOne({email: value})
    if(user){
        return Promise.reject('E-mail already in use')
    }
})],async(req,res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        return res.render('registration',{title: 'Blog - Register',layout: 'main-login-regis',data: req.body, errors: errors.array()})
    }
    const token = nanoid()
    await Token.create({token, email: req.body.email,type: 'activation'})
    await User.create({name: req.body.username,email: req.body.email,password: bcrypt.hashSync(req.body.password,10)})
    // mail to user
    const mailOptions = {
        from: 'fajaradiputra127@gmail.com',
        to: `${req.body.email}`,
        subject: 'Verify your account to login',
        html: `Click this link to verify your account : <a href="http://localhost:3000/auth/activation/${token}">Active</a>`
    };     
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) throw err;
        console.log('Email sent: ' + info.response);
    }); 
    req.flash('msg','Check your e-mail for activation')
    res.redirect('/login')
})
app.post('/login',[body('email').isLength({min: 1}).withMessage('This field is required').isEmail().withMessage('Insert a valid email').custom(async(value,{req}) =>{
    const user = await User.findOne({email: value})
    if(!user){
        return Promise.reject('E-mail or password incorrect')
    }
    if(!user.isActive){
        return Promise.reject('This account hasn\'t been verify yet')
    }
    const match = bcrypt.compareSync(req.body.password,user.password)
    if(!match){
        return Promise.reject('E-mail or password incorrect')
    }
}),body('password').isLength({min: 1}).withMessage('This field is required')],async(req,res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        return res.render('login',{title: 'Blog - Login', layout: 'main-login-regis', msg: req.flash('msg'),errors: errors.array(),data: req.body})
    }
    const user = await User.findOne({email: req.body.email}).select('email name')
    // set jwt token
    const token = jwt.sign({data: {id: user._id, email: user.email, name: user.name}},'secret',{expiresIn: '7d'})
    // decoded jwt token
    const expireTime = jwt.verify(token,'secret')
    // get date of jwt exp
    const d = new Date(0)
    d.setUTCSeconds(expireTime.exp)
    // set token and expires to cookie
    if(req.body.remember){
        res.cookie("access_token",token,{
            httpOnly: true,
            expires: d
        })
    }
    if(!req.body.remember){
        res.cookie("access_token",token,{
            httpOnly: true,
        })
    }
    res.redirect('/login')
})
app.post('/forgotpassword',body('email').isLength({min: 1}).withMessage('This field is required').isEmail().withMessage('Insert a valid E-mail').custom(async value => {
    const user = await User.findOne({email: value})
    if(!user){
        return Promise.reject('E-mail not found')
    }
    if(!user.isActive){
        return Promise.reject('This E-mail hasn\'t been verify yet')
    }
}),async(req,res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        return res.render('forgot',{title: 'Blog - Forgot Password', layout: 'main-login-regis',msg: req.flash('msg'),data: req.body, errors: errors.array()})
    }
    const token = nanoid()
    await Token.create({token, email: req.body.email,type: 'reset'})
    // mail to user
    const mailOptions = {
        from: 'fajaradiputra127@gmail.com',
        to: `${req.body.email}`,
        subject: 'Visit this link to reset your password',
        html: `Click this link to reset your password : <a href="http://localhost:3000/auth/reset/${token}">Reset Password</a>`
    };     
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) throw err;
        console.log('Email sent: ' + info.response);
    }); 
    req.flash('msg','Check your e-mail for reset password')
    res.redirect('/forgotpassword')
})
app.post('/auth/reset/:token',body('password').isLength({min: 1}).withMessage('This field is required').custom((value,{req}) => {
    if(value !=  req.body.confirmpassword){
        return Promise.reject('Password doesn\'t match')
    }
    return true
}),async(req,res,next) => {
    const token = await Token.findOne({token: req.params.token, type: 'reset'})
    if(!token){
        return next()
    }
    const errors = validationResult(req)
    if(!errors.isEmpty()){
        return res.render('resetform',{title: 'Blog - Reset Password', layout: 'main-login-regis',msg: req.flash('msg'),data: req.body,errors: errors.array()})
    }
    await User.updateOne({email: token.email},{password: bcrypt.hashSync(req.body.password,10)})
    await Token.deleteMany({email: token.email, type: token.type})
    req.flash('msg','Your password has been changed please login')
    res.redirect('/login')
})
app.post('/my-post/create',[body('title').isLength({max: 255}).withMessage('Maximum characters is 255').isLength({min: 1}).withMessage('This field is required'),body('slug').isLength({min: 1}).withMessage('This field is required').custom(async value => {
    const post = await Post.findOne({slug: value})
    if(post){
        return Promise.reject('This slug already taken')
    }
}), body('categorie').isLength({min: 1}).withMessage('Select one category').custom(async value => {
    const categorie = await Categorie.findOne({_id: value})
    if(!categorie){
        return Promise.reject('Categorie not found')
    }
}), body('body').isLength({min: 1}).withMessage('This field is required')],async(req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        const errors = validationResult(req)
        if(!errors.isEmpty()){
            const categories = await Categorie.find().select('name slug')
            return res.render('create', {title: 'Create post', layout: 'main-dashboard', data: req.body, categories, errors: errors.array(), userData: decode.data})
        }
        let excerpt = req.body.body.replace(/<[^>]*>?/gm, '');
        if(excerpt.length > 200){
            excerpt = excerpt.substring(0,200)
        }
        req.body.excerpt = excerpt + '...'
        req.body.author = decode.data.id
        await Post.create(req.body)
        req.flash('msg','New post has been created')
        res.redirect('/my-post')
    })
})
app.post('/my-post/edit/:id',[body('title').isLength({max: 255}).withMessage('Maximum characters is 255').isLength({min: 1}).withMessage('This field is required'),body('slug').isLength({min: 1}).withMessage('This field is required').custom(async (value,{req}) => {
    const post = await Post.findOne({slug: value})
    if(post){
        if(post._id.toString() != req.params.id){
            return Promise.reject('This slug already taken')
        }
    }
}), body('categorie').isLength({min: 1}).withMessage('Select one category').custom(async value => {
    const categorie = await Categorie.findOne({_id: value})
    if(!categorie){
        return Promise.reject('Categorie not found')
    }
}), body('body').isLength({min: 1}).withMessage('This field is required')],async(req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        if(!mongoose.isValidObjectId(req.params.id)){
            return next()
        }
        const post = await Post.findOne({_id: req.params.id}).lean()
        if(!post){
            return next()
        }else{
            if(post.author != decode.data.id){
                return next()
            }
        }
        const errors = validationResult(req)
        if(!errors.isEmpty()){
            const categories = await Categorie.find().select('name slug')
            return res.render('create', {title: 'Create post', layout: 'main-dashboard', data: req.body, categories, errors: errors.array(), userData: decode.data})
        }
        let excerpt = req.body.body.replace(/<[^>]*>?/gm, '');
        if(excerpt.length > 200){
            excerpt = excerpt.substring(0,200)
        }
        req.body.excerpt = excerpt + '...'
        req.body.author = decode.data.id
        await Post.updateOne({_id : post._id},req.body)
        req.flash('msg','Post has been updated')
        res.redirect('/my-post')
    })
})
// End of Auth

app.get('/', (req, res) => {
    res.render('home', {
        title: 'Home',
        active: 'home',
    })
})
app.get('/about', (req, res) => {
    res.render('about', {
        title: 'About',
        active: 'about'
    })
})
app.get('/blog', async (req, res) => {
    let judul;
    Post.find({
            $or: [{
                title: {
                    $regex: typeof req.query.search != 'undefined' ? req.query.search : '',
                    $options: 'gi'
                }
            }, {
                body: {
                    $regex: typeof req.query.search != 'undefined' ? req.query.search : '',
                    $options: 'gi'
                }
            }]
        })
        .populate([{
                path: 'author',
                match: {
                    name: {
                        $regex: typeof req.query.author != 'undefined' ? req.query.author : '',
                    }
                },
                select: 'name',
                model: User
            },
            {
                path: 'categorie',
                match: {
                    slug: {
                        $regex: typeof req.query.categorie != 'undefined' ? req.query.categorie : '',
                        $options: 'gi'
                    }
                },
                select: 'name slug',
                model: Categorie
            }
        ])
        .sort({
            'published': 'desc'
        }).exec(async (err, result) => {
            result = result.filter(object => object.author != null && object.categorie != null)
            let page = !req.query.page ? 1 : parseInt(req.query.page);     
            const limit = 7,
                jumlahData = result.length,
                jumlahHalaman = Math.ceil(jumlahData / limit),
                awalData = (limit * page) - limit
            
            result = result.slice(awalData, awalData + 7)
            if (req.query.categorie) {
                judul = typeof result[0] != 'undefined' ? `Category - ${result[0].categorie.name}` : 'Not found'
            }
            if (req.query.author) {
                judul = typeof result[0] != 'undefined' ? `Post by Author : ${result[0].author.name}` : 'Not found'
            }
            if (!req.query.categorie && !req.query.author) {
                judul = 'All Post'
            } 
            res.render('blog', {
                title: 'Blog',
                posts: result,
                judul,
                active: 'blog',
                search: req.query.search,
                categorie: req.query.categorie,
                author: req.query.author,
                paginate: result,
                jumlahHalaman,
                page,
                query: req.query
            })
        })
})
app.get('/blog/categories', async (req, res) => {
    const categories = await Categorie.find().select('slug name')
    res.render('categories', {
        title: 'Category',
        categories,
        active: 'categories'
    })
})
app.get('/blog/:slug', async (req, res) => {
    const post = await Post.findOne({
        slug: req.params.slug
    }).populate('categorie', 'name slug').populate('author', 'name')
    res.render('post', {
        title: post.title,
        post,
        active: 'blog'
    })
})
app.get('/register',(req,res,next) => {
    if(res.locals.login){
        return next()
    }
    res.render('registration',{title: 'Blog - Register',layout: 'main-login-regis'})
})
app.get('/login',(req,res) => {
    const token = req.cookies.access_token
    if(!token){
        return res.render('login', {title: 'Blog - Login', layout: 'main-login-regis', msg: req.flash('msg')})
    }
    jwt.verify(token,'secret',(err,decoded) => {
        if(err){
            req.flash('msg','Your session has been expired')
            res.clearCookie('access_token')
            return res.render('login', {title: 'Blog - Login', layout: 'main-login-regis', msg: req.flash('msg')})
        }else{
            return res.redirect('/')
        }
    })
})
app.get('/logout',async(req,res,next) => {
    const token = req.cookies.access_token
    if(!token){
        return next()
    }
    res.clearCookie('access_token')
    res.redirect('/')
})
app.get('/auth/activation/:token',async(req,res,next) => {
    const token = await Token.findOne({token: req.params.token})
    if(!token){
        return next()
    }
    await User.updateOne({email: token.email},{isActive: true})
    await Token.deleteMany({email: token.email, type: 'activation'})
    req.flash('msg','Your account has been verify please login')
    res.redirect('/login')
})
app.get('/auth/reset/:token',async(req,res,next) => {
    const token = await Token.findOne({token: req.params.token})
    if(!token){
        return next()
    }
    res.render('resetform',{title: 'Blog - Reset Password', layout: 'main-login-regis',msg: req.flash('msg')})
})
app.get('/forgotpassword',(req,res,next) => {
    if(res.locals.login){
        return next()
    }
    res.render('forgot',{title: 'Blog - Forgot Password', layout: 'main-login-regis',msg: req.flash('msg')})
})
app.get('/dashboard',(req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        res.render('dashboard',{title: 'Dashboard', active: '',layout: 'main-dashboard', userData: decode.data})  
    })
})
app.get('/my-post',async(req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        let posts = await Post.find().populate([{path: 'author',
        match: {
            _id: decode.data.id
        },
        select: 'name',
        model: User
    }]).sort({'published' : 'desc'}).lean()
        posts = posts.filter(object => object.author)
        let page = !req.query.page ? 1 : parseInt(req.query.page);     
            const limit = 10,
                jumlahData = posts.length,
                jumlahHalaman = Math.ceil(jumlahData / limit),
                awalData = (limit * page) - limit
            
            posts = posts.slice(awalData, awalData + 10)
        res.render('myPost',{title: 'Your Posts', active: '',posts,layout: 'main-dashboard', userData: decode.data, msg: req.flash('msg'), paginate: posts,jumlahHalaman, page, query: req.query})  
    })
    
})
app.get('/my-post/create',(req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        const categories = await Categorie.find().select('name slug')
        res.render('create',{title: 'Create post',layout: 'main-dashboard', userData: decode.data, categories})
    })
})
app.get('/my-post/edit/:id', (req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        if(!mongoose.isValidObjectId(req.params.id)){
            return next()
        }
        const post = await Post.findOne({_id: req.params.id}).lean()
        if(!post){
            return next()
        }else{
            if(post.author != decode.data.id){
                return next()
            }
        }
        post.categorie = post.categorie.toString()
        const categories = await Categorie.find().select('name slug')
        res.render('create',{title: 'Create post',layout: 'main-dashboard', userData: decode.data, categories, data: post})
    }) 
})
app.get('/my-post/delete/:id', (req,res,next) => {
    jwt.verify(req.cookies.access_token,'secret',async(err,decode) => {
        if(err){
            return next()
        }
        if(!mongoose.isValidObjectId(req.params.id)){
            return next()
        }
        const post = await Post.findOne({_id: req.params.id}).lean()
        if(!post){
            return next()
        }else{
            if(post.author != decode.data.id){
                return next()
            }
        }
        await Post.deleteOne({_id: req.params.id})
        req.flash('msg','Your post has been deleted')
        res.redirect('/my-post')
    }) 
})
app.get('/home',(req,res) => {
    res.redirect('/')
})
app.use('/',(req,res) => {
    res.statusCode = 404
    res.render('404',{title: 'Not Found', layout: '404'})
})
app.listen(3000, () => {
    console.log('Server listening on port 3000..')
})
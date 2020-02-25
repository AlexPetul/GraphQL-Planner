const express = require("express");
const multer  = require('multer');
const crypto = require('crypto');
const mime = require('mime');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const User = require("./model/User");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const verify = require('./middlewares/verifyToken')
const session = require('express-session')({
	secret: 'keyboard cat',
	cookie: { maxAge: 60000000 },
	resave: true,
	saveUninitialized: true
});
const { registerValidation, loginValidation } = require('./validation');
const fs = require("fs");
const bodyParser = require("body-parser");
const jsonParser = bodyParser.json();

const app = express();
const http = require('http').createServer(app);
const io = require('socket.io').listen(http);
const sharedsession = require("express-socket.io-session");


// STORAGE CONFIG
var storage = multer.diskStorage({
	destination: function (req, file, cb) {
		cb(null, 'uploads/')
	},
	filename: function (req, file, cb) {
		crypto.pseudoRandomBytes(16, function (err, raw) {
			cb(null, raw.toString('hex') + Date.now() + '.' + mime.getExtension(file.mimetype));
		});
	}
});
var upload = multer({ storage: storage });

app.set('views', 'templates');
app.set('view engine', 'hbs');

// DATABASE CONNECT
dotenv.config();
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true, useUnifiedTopology: true },
	() => console.log("connected to db!")
	);

// MIDDLEWARE
app.use(express.static('public'));

app.use(session);

io.use(sharedsession(session));


io.sockets.on('connection', function(socket){

	socket.on('get plans', function(){
		var content = fs.readFileSync("plans.json", "utf8");
		var plans = JSON.parse(content);
		io.sockets.emit('get plan list', plans);
	});

	socket.on('register', async (data) => {
		var data = JSON.parse(data);
		const { error } = registerValidation(data);
		if (error) {
			io.sockets.emit('register error', error.details[0].message);
		} else {
			const emailExists = await User.findOne({email: data.email});
			if (emailExists) {
				io.sockets.emit('register error', 'Email already exists');
			} else {
				const salt = await bcrypt.genSalt(10);
				const hashedPassword = await bcrypt.hash(data.password, salt);
				const user = new User({
					name: data.name,
					email: data.email,
					password: hashedPassword
				});
				try {
					const savedUser = await user.save();
					io.sockets.emit('register success');
				} catch (err) {
					io.sockets.emit('register error', err);
				}
			}
		}
	});

	socket.on('login', async (data) => {
		var data = JSON.parse(data);
		const { error } = loginValidation(data);
		if (error) {
			io.sockets.emit('login error', error.details[0].message);
		} else {
			const user = await User.findOne({email: data.email});
			if (!user) {
				io.sockets.emit('login error', 'Email or password is wrong.');
			} else {
				const validPassword = await bcrypt.compare(data.password, user.password);
				if (!validPassword){
					io.sockets.emit('login error', 'Password is wrong');
				} else {
					const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);
					socket.handshake.session.token = token;
					socket.handshake.session.save();
					io.sockets.emit('login success');
				}
			}
		}
	});

	socket.on('sort plans', function(data){
		var sortQuery = data;
		var newPlanList = [];
		var data = fs.readFileSync("plans.json", "utf8");
		var plans = JSON.parse(data);
		if (sortQuery == 'Все') {
			io.sockets.emit('sorted plans', plans);
		} else {
			for (var index = 0; index < plans.length; ++index) {
				if (plans[index].status == sortQuery) {
					newPlanList.push(plans[index]);
				}
			}
			io.sockets.emit('sorted plans', newPlanList);
		}
	});

	socket.on('change plan status', function(data){
		var data = JSON.parse(data);
		var planId = data.plan_id;
		var newStatus = data.new_status;
		var fileData = fs.readFileSync("plans.json", "utf8");
		var plans = JSON.parse(fileData);
		for (var index = 0; index < plans.length; ++index) {
			if (plans[index].id == planId) {
				plans[index].status = newStatus;
				break;
			}
		}
		fs.writeFileSync("plans.json", JSON.stringify(plans));
		io.sockets.emit('new plan status', newStatus);
	});

	socket.on('delete plan', function(data){
		var data = JSON.parse(data);
		var plan_id = data.plan_id;
		var fileData = fs.readFileSync("plans.json", "utf8");
		var plans = JSON.parse(fileData);
		var isPlanFound = false;
		for (var index = 0; index < plans.length; ++index) {
			if (plans[index].id == plan_id) {
				plans.splice(index, 1);
				isPlanFound = true;
				break;
			}
		}
		if (!isPlanFound) {
			io.sockets.emit('delete errpr', 'plan not found');
		} else {
			fs.writeFileSync("plans.json", JSON.stringify(plans));
			io.sockets.emit('success delete');
		}
	});

});


// ROUTES
app.get("/", function(request, response){
	response.render('index');
});

app.get('/download', function(request, response){
	var file = `${__dirname}/${request.query.file_path}`;
	response.download(file);
});

app.post("/api/create-plan", verify, upload.single('attachment'), function(request, response){
	if (!request.body) {
		return response.sendStatus(400);
	}
	else {
		var planData = JSON.parse(request.body.data);
		var data = fs.readFileSync("plans.json", "utf8");
		var plans = JSON.parse(data);
		var id = 0;
		if (plans.length == 0) {
			id = 1;
		}
		else {
			var ids = [];
			for (var index = 0; index < plans.length; ++index) {
				ids.push(plans[index].id);
			}
			id = Math.max.apply(null, ids) + 1;
		}
		var title = planData.title;
		var content = planData.content;
		var deadline = planData.deadline;
		var status = 'Не прочитано';
		var newPlan = { id: id, status: status, title: title, content: content, deadline: deadline };
		if (typeof request.file !== 'undefined' && request.file){
			newPlan['attachment'] = request.file.path;
		}
		plans.push(newPlan);
		var newData = JSON.stringify(plans);
		fs.writeFileSync("plans.json", newData);
		response.send(newPlan);
	}
});

http.listen(3000, () => console.log(`Server started.`));

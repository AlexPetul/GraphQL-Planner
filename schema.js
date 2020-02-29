const dotenv = require('dotenv');
const mongoose = require('mongoose');
const User = require("./model/User");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require("fs");
const { GraphQLUpload } = require('graphql-upload')
const { registerValidation, loginValidation } = require('./validation');

dotenv.config();
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true, useUnifiedTopology: true },
	() => console.log("connected to db!")
	);

let {
	GraphQLString,
	GraphQLList,
	GraphQLInt,
	GraphQLObjectType,
	GraphQLNonNull,
	GraphQLSchema
} = require('graphql');

const PlanType = new GraphQLObjectType({
	name: "Plan",
	description: "This represent plan",
	fields: () => ({
		id: {type: new GraphQLNonNull(GraphQLString)},
		status: {type: new GraphQLNonNull(GraphQLString)},		
		title: {type: new GraphQLNonNull(GraphQLString)},
		content: {type: new GraphQLNonNull(GraphQLString)},
		deadline: {type: new GraphQLNonNull(GraphQLString)},
		attachment: {type: GraphQLString},
	})
});

const PlannerQueryRootType = new GraphQLObjectType({
	name: "PlannerAppSchema",
	description: "Planner Application Schema Query Root",
	fields: () => ({
		plans: {
			type: new GraphQLList(PlanType),
			description: "List of all plans",
			resolve: function() {
				let content = fs.readFileSync("plans.json", "utf8");
				let plans = JSON.parse(content);
				return plans;
			}
		},
		planById: {
			type: PlanType,
			description: "Get plan by id",
			args: {
				id: {type: GraphQLInt}
			},
			resolve: function(_, args) {
				let content = fs.readFileSync("plans.json", "utf8");
				let plans = JSON.parse(content);
				for (let index = 0; index < plans.length; ++index) {
					if (plans[index].id === args.id) {
						return plans[index];
					}
				}
			}
		},
		sortByStatus: {
			type: new GraphQLList(PlanType),
			description: "Sort Plans By Status",
			args: {
				status: {type: GraphQLString}
			},
			resolve: function(_, args) {
				let result = [];
				let content = fs.readFileSync("plans.json", "utf8");
				let plans = JSON.parse(content);
				for (let index = 0; index < plans.length; ++index) {
					if (plans[index].status == args.status) {
						result.push(plans[index]);
					}
				}
				return result;
			}
		}
	})
});

const PlannerMutationRootType = new GraphQLObjectType({
	name: "PlannerAppSchemaMutation",
	description: "Planner Application Schema Mutation Root",
	fields: () => ({
		createUser: {
			type: GraphQLString,
			args: {
				name: {type: GraphQLString},
				email: {type: GraphQLString},
				password: {type: GraphQLString}
			},
			resolve: async(_, args) => {
				let data = args;
				const { error } = registerValidation(data);
				if (error) {
					return error.details[0].message;
				} else {
					const emailExists = await User.findOne({email: data.email});
					if (emailExists) {
						return 'Email already exists';
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
							return 'register success';
							io.sockets.emit('register success');
						} catch (err) {
							return err;
						}
					}
				}
			}
		},
		loginUser: {
			type: GraphQLString,
			args: {
				email: {type: GraphQLString},
				password: {type: GraphQLString}
			},
			resolve: async(_, args) => {
				let data = args;
				const { error } = loginValidation(data);
				if (error) {
					return error.details[0].message;
				} else {
					const user = await User.findOne({email: data.email});
					if (!user) {
						return 'Email or password is wrong.';
					} else {
						const validPassword = await bcrypt.compare(data.password, user.password);
						if (!validPassword){
							return 'Email or password is wrong';
						} else {
							const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);
							return token;
						}
					}
				}
			}
		},
		changePlanStatus: {
			type: GraphQLString,
			args: {
				newStatus: {type: GraphQLString},
				planId: {type: GraphQLInt}
			},
			resolve: function(_, args) {
				let planId = args.planId;
				let newStatus = args.newStatus;
				let fileData = fs.readFileSync("plans.json", "utf8");
				let plans = JSON.parse(fileData);
				for (var index = 0; index < plans.length; ++index) {
					if (plans[index].id === planId) {
						plans[index].status = newStatus;
						break;
					}
				}
				fs.writeFileSync("plans.json", JSON.stringify(plans));
				return "Plan successfully edited";
			}
		},
		createPlan: {
			type: GraphQLString,
			args: {
				token: {type: GraphQLString},
				title: {type: GraphQLString},
				content: {type: GraphQLString},
				deadline: {type: GraphQLString},
				file: {type: new GraphQLNonNull(GraphQLUpload)}
			},
			resolve: async (_, args) => {
				const {token, title, content, deadline, file} = args;
				try {
					const verified = jwt.verify(token, process.env.TOKEN_SECRET);
				} catch (err) {
					return 'Invalid token';
				}
				const {filename, mimetype, createReadStream} = await file;
				const fileStream = createReadStream();
				fileStream.pipe(fs.createWriteStream(`./uploads/${filename}`));
				let data = fs.readFileSync("plans.json", "utf8");
				let plans = JSON.parse(data);
				let id = 0;
				if (plans.length == 0) {
					id = 1;
				}
				else {
					let ids = [];
					for (let index = 0; index < plans.length; ++index) {
						ids.push(plans[index].id);
					}
					id = Math.max.apply(null, ids) + 1;
				}
				const status = 'Не прочитано';
				const newPlan = { id: id, status: status, title: title, content: content, 
					deadline: deadline, attachment: `./uploads/${filename}` };
					plans.push(newPlan);
					let newData = JSON.stringify(plans);
					fs.writeFileSync("plans.json", newData);
					return "Plan created!";
				}
			},
			deletePlan: {
				type: GraphQLString,
				args: {
					planId: {type: GraphQLInt}
				},
				resolve: function(_, args) {
					let planId = args.planId;
					let fileData = fs.readFileSync("plans.json", "utf8");
					let plans = JSON.parse(fileData);
					let isPlanFound = false;
					for (let index = 0; index < plans.length; ++index) {
						if (plans[index].id === planId) {
							plans.splice(index, 1);
							isPlanFound = true;
							break;
						}
					}
					if (!isPlanFound) {
						return "Plan with this id was not found.";
					} else {
						fs.writeFileSync("plans.json", JSON.stringify(plans));
						return "Plan successfully deleted.";
					}
				}
			}
		})
});

const PlannerAppSchema = new GraphQLSchema({
	query: PlannerQueryRootType,
	mutation: PlannerMutationRootType
})

module.exports = PlannerAppSchema;
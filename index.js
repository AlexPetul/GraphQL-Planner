const express = require("express");
const bodyParser = require("body-parser");
const jsonParser = bodyParser.json();
const { buildSchema } = require('graphql');
const graphqlHTTP = require('express-graphql');
const schema = require('./schema.js')
const { graphqlUploadExpress } = require('graphql-upload')

const app = express();

app.use('/',
	graphqlUploadExpress({ maxFileSize: 10000000, maxFiles: 10 }),
	graphqlHTTP({
		schema: schema,
		graphiql: true
}));

app.listen(3000, () => console.log(`Server started.`));

const express = require('express');
const env = require("dotenv");
const cors = require('cors')
const { userRouter } = require('./routes/auth');

env.config()


const PORT = process.env.PORT || 5000 ;
const app = express();

app.use(express.json())
app.use(cors())
app.use("/user", userRouter)


app.get("/", (request, response) => {
    response.status(200).send({"message": "Welcome"})
})

app.listen(PORT, () => {
    console.log("Server running at port:", PORT)
})
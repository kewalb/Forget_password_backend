const express = require('express');
const env = require("dotenv")
const bcrypt = require("bcrypt")

env.config()


const PORT = process.env.PORT;
const app = express();


app.post("/signup", (request, response) => {
    const {name, email, password} = request.body
    if(!name || !email || !password){
        return response.send({"message": "Please fill in all the fields"})
    }
    User.findOne({email: email}).then((dbUser) => {
        if(dbUser){
            return response.status(422).send({"message": "Try with different email"})
        }
        bcrypt.hash(password, 10).then()
    })
    response.send("message")
})

app.listen(PORT, () => {
    console.log("Server running at port:", PORT)
})
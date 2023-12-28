import userModel from "../models/user.model.js"

export default class Users {
    constructor() {
    }

    getByEmail = async (email) => {
        try {     
            let user = await userModel.findOne({email: email})
            return user
        } catch (error) {
            console.log(error)
            return null
        }
    }

    getUser = async (uid) => {
        try {
            let user = await userModel.findById(uid)
            return user
        } catch (error) {
            console.log(error)
            return null
        }
    }

    getByCart = async (cid) => {
        try {     
            let user = await userModel.findOne({cart: cid})
            return user
        } catch (error) {
            console.log(error)
            return null
        }
    }

    createUser = async(user) => {
        let newUser = await userModel.create(user)
        return newUser
    }






}


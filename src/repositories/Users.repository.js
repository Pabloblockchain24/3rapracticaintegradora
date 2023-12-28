import userDTO from "../dao/DTOs/user.dto.js";

export default class UserRepository {
    constructor(dao){
        this.dao = dao
    }
    
    getUserByEmail = async (email) => {
        try {     
            let user = await this.dao.getByEmail(email)
            return user
        } catch (error) {
            console.log(error)
            return null
        }
    }

    getById = async(uid) => {
        try {
            let user = await this.dao.getUser(uid)
            return user
        } catch (error) {
            console.log(error)
            return null
        }
    }

    getUserByCartId = async(cid) => {
        try {
            let result = await this.dao.getByCart(cid)
            return result
        } catch (error) {
            console.log(error)
            return null
        }
    }

    createUser = async(user) => {
        let newUser = new userDTO(user)
        let result = await this.dao.createUser(newUser)
        return result
    }
}
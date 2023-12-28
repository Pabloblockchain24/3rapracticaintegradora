import messageDTO from "../dao/DTOs/message.dto.js";

export default class messageRepository {
    constructor(dao){
        this.dao = dao
    }

    postMessage = async(message) =>{
        try {
            let newMessage = new messageDTO(message)
            let result = await this.dao.createMessage(newMessage)
            return result
        } catch (error) {
            console.log(error)
            return null
        }
    }

}


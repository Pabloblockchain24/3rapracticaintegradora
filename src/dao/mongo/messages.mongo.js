import messageModel from "../models/message.model.js"

export default class Messages {
    constructor() {
    }

    createMessage = async(newMessage) =>{
        let message = await messageModel.create(newMessage)
        return message
    }

}
import mongoose from "mongoose";
const messageCollection = "mensajes"

const messageSchema = new mongoose.Schema({
    message: String
})

const Message = mongoose.model(messageCollection,messageSchema)

export default Message
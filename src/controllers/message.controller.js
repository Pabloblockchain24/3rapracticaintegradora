import {messagesService} from "../repositories/index.js"

export const createMessage = async (req,res) =>{
    const message = req.body.message;
    let result = await messagesService.postMessage(message)
    res.send({ result: "success", payload: result })
}
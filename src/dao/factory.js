import mongoose from "mongoose"
import config from "../config/config.js"


export let Users
export let Carts
export let Products
export let Tickets
export let Messages

switch (config.PERSISTENCE) {
    case "MONGO":
        mongoose.connect(config.MONGO_URL)
        const {default:usersMongo} = await import("./mongo/users.mongo.js")
        Users = usersMongo

        const {default:cartsMongo} = await import("./mongo/carts.mongo.js")
        Carts = cartsMongo

        const {default:productsMongo} = await import("./mongo/products.mongo.js")
        Products = productsMongo

        const {default:ticketsMongo} = await import("./mongo/tickets.mongo.js")
        Tickets = ticketsMongo

        const {default:messagesMongo} = await import("./mongo/messages.mongo.js")
        Messages = messagesMongo

        break;
}
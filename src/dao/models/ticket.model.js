import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2"

const ticketSchema = mongoose.Schema({
    code: String,
    purchase_datetime: Date,
    amount: Number,
    purcharser: String
})

ticketSchema.plugin(mongoosePaginate)

const Ticket = mongoose.model("Ticket",ticketSchema)

export default Ticket
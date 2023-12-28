import ticketModel from "../models/ticket.model.js"

export default class Ticket {
    constructor() {
    }
    createTicket = async(ticket) => {
        let newTicket = await ticketModel.create(ticket)
        return newTicket
    }

}


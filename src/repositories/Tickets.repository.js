import ticketDTO from "../dao/DTOs/ticket.dto.js";

export default class TicketRepository {
    constructor(dao){
        this.dao = dao
    }

    createTicket = async(ticket) =>{
        try{
            let newTicket = new ticketDTO(ticket) 
            let result = await this.dao.createTicket(newTicket)
            return result
        }catch(error){
            console.log(error)
            return null
        }
    }
 
}

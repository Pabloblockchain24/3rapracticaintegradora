import { Users } from "../dao/factory.js";
import UserRepository from "./Users.repository.js";

import { Products } from "../dao/factory.js";
import ProductRepository from "./Products.repository.js";

import { Carts } from "../dao/factory.js"
import CartRepository from "./Carts.repository.js";

import { Tickets } from "../dao/factory.js";
import TicketRepository from "./Tickets.repository.js";

import { Messages } from "../dao/factory.js";
import messageRepository from "./Messages.repository.js";


export const usersService = new UserRepository(new Users)
export const productsService = new ProductRepository(new Products)
export const cartsService = new CartRepository(new Carts)
export const ticketsService = new TicketRepository(new Tickets)
export const messagesService = new messageRepository(new Messages)

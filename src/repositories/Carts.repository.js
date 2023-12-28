import cartDTO from "../dao/DTOs/cart.dto.js";

export default class CartRepository {
    constructor(dao){
        this.dao = dao
    }

    updateCartById = async(cid, newCart) => {
        try {
            let cartUpdated = await this.dao.updateCart(cid,newCart)
            return cartUpdated
        } catch (error) {
            console.log(error)
            return null
        }
    }

    getCartById = async(cid) =>{
        try {
            let cartFound = await this.dao.getCart(cid)
            return cartFound
        } catch (error) {
            console.log(error)
            return null
        }
    }

    createCart = async() =>{
        try {
            let newCart = await this.dao.createNewCart()
            return newCart
        } catch (error) {
            console.log(error)
            return null
        }
    }

    getAllCarts = async() =>{
        try {
            let carritos = await this.dao.get({})
            return carritos
        } catch (error) {
            console.log(error)
            return null
        }
    }
}
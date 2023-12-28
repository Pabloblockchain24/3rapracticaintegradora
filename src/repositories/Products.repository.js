import productDTO from "../dao/DTOs/product.dto.js";

export default class ProductRepository {
    constructor(dao){
        this.dao = dao
    }

    getProductById = async (pid) => {
        try {
            let productFound = await this.dao.getProduct(pid)
            return productFound
        } catch (error) {
            console.log(error)
            return null
        }
    }

    deleteProductById = async(pid) =>{
        try {
            let result = await this.dao.deleteProduct(pid)
            return result
        } catch (error) {
            console.log(error)
            return null
        }
    }

    updateProductById = async(pid, productToReplace) =>{
        try {
            let result = await this.dao.updateProduct(pid,productToReplace)
            return result
        }catch (error) {
            console.log(error)
            return null
        }
    }

    postProduct = async(product) =>{
        try {
            let newProduct = new productDTO(product)
            let result = await this.dao.createProduct(newProduct)
            return result
        } catch (error) {
            console.log(error)
            return null
        }
    }
}
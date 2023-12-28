export default class productDTO {
    constructor(product) {
        this.nombre = product.nombre,
        this.descripcion = product.descripcion,
        this.category = product.category,
        this.precio = product.precio,
        this.stock = product.stock
    }
}
export default class userDTO {
    constructor(user) {
        this.first_name = user.first_name,
        this.last_name = user.last_name,
        this.email = user.email,
        this.age = user.age,
        this.password = user.password,
        this.cart = user.cart,
        this.role = user.role,
        this.resetToken = "",
        this.documentos = [],
        this.last_connection = user.last_connection,
        this.fotoPerfil = ""
    }
}
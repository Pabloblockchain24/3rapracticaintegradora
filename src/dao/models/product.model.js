import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2"

const productSchema = mongoose.Schema({
    nombre: String,
    descripcion: String,
    category: String,
    precio: Number,
    stock: Number,
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: async () => {
            const adminUser = await User.findOne({ role: 'admin' });
            return adminUser ? adminUser._id : null;
        }
    },
})

productSchema.plugin(mongoosePaginate)

const Product = mongoose.model("Product",productSchema)

export default Product
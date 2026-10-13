import mongoose from 'mongoose';

const entrySchema = new mongoose.Schema({
  ref: { type: String, required: true, unique: true },
  fullname: { type: String, required: true },
  title: { type: String, required: true },
  category: { type: String, required: true },
  purok: { type: String, required: true },
  date: { type: String, required: true },
  status: { type: String, default: 'pending' },
  note: { type: String }
});

export default mongoose.model('Entry', entrySchema);
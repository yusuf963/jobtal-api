import mongoose from 'mongoose';
import { CategoryEnum } from '../lib/util/constants.js';

const courseSchema = new mongoose.Schema(
	{
		title: {
			type: String,
			required: true,
			validate: (title) =>
				typeof title === 'string' && title.length > 1 && title.length < 500,
		},
		description: {
			type: String,
			required: true,
			validate: (description) =>
				typeof description === 'string' &&
				description.length > 1 &&
				description.length < 2000,
		},
		instructor: {
			type: String,
			required: true,
		},
		duration: {
			type: Number,
			required: true,
		},
		level: {
			type: String,
			enum: ['Beginner', 'Intermediate', 'Advance'],
			required: true,
		},
		prerequisites: {
			type: [String],
			default: [],
		},
		skillsCovered: [String],
		courseLink: {
			type: String,
			required: true,
		},
		creator: {
			type: mongoose.Schema.Types.ObjectId,
			ref: 'User',
			required: true,
		},
		category: {
			type: String,
			enum: CategoryEnum,
			required: true,
		},
	},
	{ timestamps: true },
);

export default mongoose.model('Course', courseSchema);

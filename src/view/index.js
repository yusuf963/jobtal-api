import express from 'express';
import { secureRoute, adminRoute } from '../lib/util/secureRoute.js';
import passport from 'passport';

import {
	getSingleJobValidator,
	createJobPostValidator,
	updateJobPostValidator,
	deleteJobPostValidator,
} from '../lib/util/validation/jobPostValidator.js';
import {
	getSingleCourseValidator,
	createCourseValidator,
	updateCourseValidator,
	deleteCourseValidator,
} from '../lib/util/validation/courseValidator.js';

import {
	registerUser,
	loginUser,
	updateUser,
	deleteUser,
	getAllUsers,
	getOneUser,
	confirmUserVerification,
} from '../controller/user.js';

import {
	handelGetAllJobs,
	handelGetSingleJob,
	handelCreateJobPost,
	handelUpdateJobPost,
	handelDeleteJobPost,
} from '../controller/jobPost.js';

import {
	handelGetAllCourses,
	handelCreateCourse,
	handelGetSingleCourse,
	handelUpdateCourse,
	handelDeleteCourse,
} from '../controller/course.js';

import {
	forgotPassword,
	verifyResetCode,
	resetPassword,
} from '../controller/forgotPassword.js';

import environment from '../lib/environment.js';

const router = express.Router();

router.route('/').get((req, res) => {
	res.sendFile('index.html', { root: '.' });
});

router
	.route('/job')
	.get((_req, res) =>
		res.send(
			'<h2 style="color: red; text-align: center;">Jobs route coming soon</h2>',
		),
	);

router.route('/auth/google').get(
	passport.authenticate('google', {
		scope: ['profile', 'email'],
		session: false,
	}),
);
router.route('/auth/google/callback').get(
	passport.authenticate('google', {
		failureRedirect: '/login',
		successRedirect: '/',
		session: false,
	}),
);

router.route('/register').post(registerUser);
router.route('/login').post(loginUser);
router.route('/verify-account/:id/:token').get(confirmUserVerification);

router.route(environment.usersGetAll).get(adminRoute, getAllUsers);
router
	.route('/user/:id')
	.get(adminRoute, getOneUser)
	.put(secureRoute, updateUser)
	.delete(secureRoute, deleteUser);

router
	.route('/jobpost')
	.get(handelGetAllJobs)
	.post(createJobPostValidator, handelCreateJobPost);
router
	.route('/jobpost/:id')
	.get(secureRoute, getSingleJobValidator, handelGetSingleJob)
	.put(secureRoute, updateJobPostValidator, handelUpdateJobPost)
	.delete(adminRoute, deleteJobPostValidator, handelDeleteJobPost);

router.route('/forgot-password').post(forgotPassword);
router.route('/verify-reset-code').post(verifyResetCode);
router.route('/reset-password').put(resetPassword);

router
	.route('/courses')
	.get(handelGetAllCourses)
	.post(adminRoute, createCourseValidator, handelCreateCourse);
router
	.route('/courses/:id')
	.get(secureRoute, getSingleCourseValidator, handelGetSingleCourse)
	.put(secureRoute, updateCourseValidator, handelUpdateCourse)
	.delete(adminRoute, deleteCourseValidator, handelDeleteCourse);

export default router;

/**
 * Created by eldiablo on 01/12/14.
 */

var gulp = require('gulp');
var ts = require('gulp-typescript');

gulp.task('clean', function() {
  var del = require('del');
  del(['build']);
});

gulp.task('dist-clean', function() {
  var del = require('del');
  del(['build/release']);
});

gulp.task('dist', ['dist-compile', 'dist-files'], function() {
    var fs = require('fs');
    var pkg = require('./package');
    delete pkg.devDependencies;
    delete pkg.scripts;

    require('mkdirp')('./build/release/');
  
    fs.writeFileSync('./build/release/package.json', JSON.stringify(pkg, null, 2));  
});

gulp.task('dist-compile', function() {
  var tsProject = ts.createProject('./tsconfig.json');
  gulp
    .src(['src/**/*.ts'])
    .pipe(tsProject())
    .js.pipe(gulp.dest('build/release'));
  gulp.src('src/services/*.yaml').pipe(gulp.dest('build/release/services'));
});

gulp.task('dist-files', function() {
  gulp.src('src/services/*.yaml').pipe(gulp.dest('build/release/services'));
});

gulp.task('prepare-debug', function() {
  var fs = require('fs');
  gulp.src('src/services/*').pipe(gulp.dest('build/debug/services'));
  gulp.src('test/support/*').pipe(gulp.dest('build/debug/support'));
});
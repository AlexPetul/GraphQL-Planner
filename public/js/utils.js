$(document).ready(function(){

	function addPlanItem(plan){
		if (plan.attachment) {
			$('#plan-list').append(
				'<div class="col-md-4 plan-item-wrapper-' + plan.id + '">\
					<div class="plan-wrapper">\
						<select plan-id="' + plan.id + '" class="custom-select custom-select-sm">\
							<option value="Не прочитано" selected>Не прочитано</option>\
							<option value="В процессе">В процессе</option>\
							<option value="Сделано">Сделано</option>\
						</select>\
						<p align="center">' + plan.title + '</p>\
						<p align="center">' + plan.content + '</p>\
						<a href="" class="download-attachment" file-path="' + plan.attachment + '">\
						<i class="fa fa-paperclip" aria-hidden="true"></i> Вложение</a><br>\
						<span class="alignment-tool"></span>\
						<span>' + plan.deadline + '</span>\
						<span class="delete-plan" plan-id="' + plan.id + '"><i class="fa fa-trash" aria-hidden="true"></i></span>\
					</div>\
				</div>'
				);
		}
		else {
			$('#plan-list').append(
				'<div class="col-md-4 plan-item-wrapper-' + plan.id + '">\
					<div class="plan-wrapper">\
						<select plan-id="' + plan.id + '" class="custom-select custom-select-sm">\
							<option value="Не прочитано" selected>Не прочитано</option>\
							<option value="В процессе">В процессе</option>\
							<option value="Сделано">Сделано</option>\
						</select>\
						<p align="center">' + plan.title + '</p>\
						<p align="center">' + plan.content + '</p>\
						<span class="alignment-tool"></span>\
						<span>' + plan.deadline + '</span>\
						<span class="delete-plan" plan-id="' + plan.id + '"><i class="fa fa-trash" aria-hidden="true"></i></span>\
					</div>\
				</div>'
				);
		}
	}

	function fillPlansStatus(data){
		var index = 0;
		var block_heights = []
		$('#plan-list select').each(function(){
			$(this).val(data[index].status);
			if (data[index].status == 'Сделано') {
				$('.plan-item-wrapper-' + data[index].id + ' div').css('border-color', 'green');
			}
			else if (data[index].status == 'В процессе') {
				$('.plan-item-wrapper-' + data[index].id + ' div').css('border-color', 'orange');
			}
			block_heights.push($('#plan-list .plan-item-wrapper-' + data[index].id).height());
			++index;
		});
		var max_height = Math.max.apply(Math, block_heights);
		$('#plan-list .plan-wrapper').each(function(){
			var current_height = $(this).height();
			$(this).find('.alignment-tool').height(max_height - current_height);
		});
	}

	$('#plan-list').on('click', '.download-attachment', function(e){
		e.preventDefault();
		var path = $(this).attr('file-path');
		$.ajax({
			url: "/download",
			type: "GET",
			xhrFields: {
				responseType: 'blob'
			},
			data: {
				file_path: path
			},
			success: function(response, status, xhr){
				var fileName = xhr.getResponseHeader('Content-Disposition').split("=")[1]
				var a = document.createElement('a');
				var url = window.URL.createObjectURL(response);
				a.href = url;
				a.download = fileName;
				a.click();
				window.URL.revokeObjectURL(url)
			}
		});
	});

	$('#register-button').on('click', function(){
		$('#modalLoginForm').modal('hide');
		$('#modalRegistrationForm').modal('toggle');
	});

	var socket = io.connect();

	function getPlans(){
		socket.emit('get plans');
		socket.on('get plan list', function(data){
			$.each(data, function (index, plan) {
				addPlanItem(plan);
				$('#plan-list select:last-child').val(plan.status);
			})
			fillPlansStatus(data);	
		});
	}

	getPlans();

	$('#modalRegistrationForm input[type="submit"]').on('click', function(){
		var name = $('input[name="reg-name"]').val();
		var email = $('input[name="reg-email"]').val();
		var password = $('input[name="reg-password"]').val();
		var data = JSON.stringify({
				name: name,
				email: email,
				password: password
		});

		socket.emit('register', data);

		socket.on('register success', function(){
			$('#create-plan').trigger('reset');
			$('#modalRegistrationForm').modal('hide');
			flash('User successfully created', {
				'bgColor': 'green'
			});
		});

		socket.on('register error', function(data){
			flash(data, {
				'bgColor': 'red'
			});
		});
	});

	$('#modalLoginForm input[type="submit"]').on('click', function(){
		var email = $('input[name="email"]').val();
		var password = $('input[name="password"]').val();
		var data = JSON.stringify({
				email: email,
				password: password
		});

		socket.emit('login', data);

		socket.on('login success', function(){
			$('#create-plan').trigger('reset');
			$('#modalLoginForm').modal('hide');
			flash('User successfully logged in', {
				'bgColor': 'green'
			});
		});

		socket.on('login error', function(data){
			flash(data, {
				'bgColor': 'red'
			});
		});
	});

	$('#sort select').on('change', function(e){
		e.preventDefault();

		socket.emit('sort plans', $(this).val());

		socket.on('sorted plans', function(data){
			$('#plan-list').empty();
			$.each(data, function (index, plan) {
				addPlanItem(plan);
				$('#plan-list select:last-child').val(plan.status);
			})
			fillPlansStatus(data);
		});
	});

	$('#plan-list').on('change', 'select', function(e){
		e.preventDefault();
		var selected_option = $(this).val();
		var plan_id = $(this).attr('plan-id');
		var data = JSON.stringify({
				plan_id: plan_id,
				new_status: selected_option
		});

		socket.emit('change plan status', data);

		socket.on('new plan status', function(data){
			if (data == 'В процессе') {
				$('.plan-item-wrapper-' + plan_id + ' div').css('border-color', 'orange');
			}
			else if (data == 'Сделано') {
				$('.plan-item-wrapper-' + plan_id + ' div').css('border-color', 'green');
			}
			else {
				$('.plan-item-wrapper-' + plan_id + ' div').css('border-color', 'red');
			}
		});
	});

	$('#plan-list').on('click', '.delete-plan', function(e) {
		e.preventDefault();
		var plan_id = $(this).attr('plan-id');
		var data = JSON.stringify({plan_id: plan_id});

		socket.emit('delete plan', data);

		socket.on('success delete', function(){
			$('.plan-item-wrapper-' + plan_id).remove();
		});
	});

	$('#create-plan').submit(function(e){
		e.preventDefault();
		var title = $('#plan-title').val();
		var content = $('#plan-content').val();
		var deadline = $('#plan-deadline').val();
		var fd = new FormData;
		fd.append('attachment', $('#plan-file').prop('files')[0]);
		fd.append('data', JSON.stringify({title: title, content: content, deadline: deadline}));
		$.ajax({
			url: "/api/create-plan",
			type: "POST",
			contentType: false,
			processData: false,
			data: fd,
			success: function(data){
				$('#create-plan').trigger('reset');
				addPlanItem(data);
			},
			error: function(data){
				$('#modalLoginForm').modal('toggle');
			}
		});
	});

});
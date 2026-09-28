/* global NIGHTWARD */
( function () {
	'use strict';
	var N = window.NIGHTWARD || {};
	var t = N.i18n || {};

	function post( action, data ) {
		var body = new URLSearchParams();
		body.append( 'action', 'nightward_' + action );
		body.append( 'nonce', N.nonce );
		Object.keys( data || {} ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( N.ajax, { method: 'POST', credentials: 'same-origin', body: body } ).then( function ( r ) {
			return r.json();
		} );
	}

	function fmt( s ) {
		var args = Array.prototype.slice.call( arguments, 1 );
		return s.replace( /%(\d)\$s/g, function ( m, i ) {
			return args[ i - 1 ];
		} );
	}

	function statusEl( near ) {
		var box = near.closest( '.nw-actions, .nw-scan-actions, p' );
		return box ? box.querySelector( '[data-nw-status]' ) : null;
	}

	function setStatus( el, text, cls ) {
		if ( ! el ) {
			return;
		}
		el.textContent = text;
		el.className = 'nw-inline-status' + ( cls ? ' ' + cls : '' );
	}

	document.addEventListener( 'click', function ( e ) {
		var b;

		// Toggle event details
		if ( ( b = e.target.closest( '[data-nw-toggle]' ) ) ) {
			var id = b.getAttribute( 'data-nw-toggle' );
			var d = document.querySelector( '[data-nw-detail="' + id + '"]' );
			var row = document.querySelector( '[data-nw-row="' + id + '"]' );
			if ( d ) {
				d.hidden = ! d.hidden;
				row.classList.toggle( 'is-open', ! d.hidden );
				b.textContent = d.hidden ? t.show : t.hide;
			}
			return;
		}

		// Select all
		if ( ( b = e.target.closest( '[data-nw-all]' ) ) ) {
			document.querySelectorAll( '.nw-events input[name="ids[]"]' ).forEach( function ( c ) {
				c.checked = b.checked;
			} );
			return;
		}

		// Test e-mail
		if ( ( b = e.target.closest( '[data-nw-test-email]' ) ) ) {
			var st = statusEl( b );
			b.disabled = true;
			setStatus( st, t.sending );
			post( 'test_email' ).then( function ( r ) {
				b.disabled = false;
				setStatus( st, r.success ? t.sent : t.failed + ': ' + ( r.data && r.data.message ? r.data.message : '' ), r.success ? 'is-ok' : 'is-err' );
			} ).catch( function () {
				b.disabled = false;
				setStatus( st, t.failed, 'is-err' );
			} );
			return;
		}

		// Trust host
		if ( ( b = e.target.closest( '[data-nw-trust]' ) ) ) {
			b.disabled = true;
			post( 'trust_host', { host: b.getAttribute( 'data-nw-trust' ) } ).then( function ( r ) {
				if ( r.success ) {
					var s = document.createElement( 'span' );
					s.className = 'nw-muted';
					s.textContent = t.trusted;
					b.replaceWith( s );
				} else {
					b.disabled = false;
				}
			} );
			return;
		}

		// Accept package
		if ( ( b = e.target.closest( '[data-nw-accept]' ) ) ) {
			if ( ! window.confirm( t.confirmAccept ) ) {
				return;
			}
			b.disabled = true;
			post( 'accept', { package: b.getAttribute( 'data-nw-accept' ) } ).then( function () {
				window.location.reload();
			} );
			return;
		}

		// Hardening
		if ( ( b = e.target.closest( '[data-nw-hardening]' ) ) ) {
			var hs = statusEl( b );
			b.disabled = true;
			setStatus( hs, t.running );
			post( 'hardening' ).then( function () {
				window.location.reload();
			} ).catch( function () {
				b.disabled = false;
				setStatus( hs, t.failed, 'is-err' );
			} );
			return;
		}

		// Integrity scan
		if ( ( b = e.target.closest( '[data-nw-scan]' ) ) ) {
			var wrap = b.parentNode.querySelector( '.nw-progress' );
			var bar = wrap.querySelector( '.nw-bar span' );
			var txt = wrap.querySelector( '.nw-progress-text' );
			b.disabled = true;
			wrap.hidden = false;
			txt.textContent = t.scanning;
			var first = true;
			var step = function () {
				post( 'integrity', first ? { start: 1 } : {} ).then( function ( r ) {
					first = false;
					if ( ! r.success ) {
						txt.textContent = t.failed;
						b.disabled = false;
						return;
					}
					var s = r.data;
					var pct = s.total ? Math.round( ( s.done / s.total ) * 100 ) : 0;
					bar.style.width = pct + '%';
					txt.textContent = fmt( t.progress, s.done, s.total, s.files ) + ( s.current ? ' · ' + s.current : '' );
					if ( s.running ) {
						step();
					} else {
						bar.style.width = '100%';
						txt.textContent = t.scanDone;
						window.setTimeout( function () {
							window.location.reload();
						}, 700 );
					}
				} ).catch( function () {
					txt.textContent = t.failed;
					b.disabled = false;
				} );
			};
			step();
		}
	} );

	// Open event row: scroll into view.
	var opened = document.querySelector( '.nw-row.is-open' );
	if ( opened ) {
		opened.scrollIntoView( { block: 'center' } );
	}
}() );

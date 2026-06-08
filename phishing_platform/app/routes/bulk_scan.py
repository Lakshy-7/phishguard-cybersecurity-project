"""
PhishGuard — Bulk URL Scanner
Scan up to 50 URLs at once, download CSV results.
"""

import csv
import io
from datetime import datetime, timezone

from flask import Blueprint, render_template, request, jsonify, make_response
from flask_login import login_required, current_user

from app import db
from app.ml.predictor import predict_url
from app.models.scan import URLScan
from app.models.log import AuditLog

bulk_bp = Blueprint('bulk', __name__, url_prefix='/bulk')

MAX_URLS = 50


@bulk_bp.route('/', methods=['GET', 'POST'])
@login_required
def scan():
    results = []
    error   = None

    if request.method == 'POST':
        raw   = request.form.get('urls', '')
        model = request.form.get('model', 'random_forest')
        urls  = [u.strip() for u in raw.splitlines() if u.strip()]

        if not urls:
            error = "Please enter at least one URL."
        elif len(urls) > MAX_URLS:
            error = f"Maximum {MAX_URLS} URLs per scan. You entered {len(urls)}."
        else:
            for url in urls:
                try:
                    result = predict_url(url, model)
                    result['url'] = url
                    results.append(result)

                    # Persist to DB
                    import json as _json
                    scan_row = URLScan(
                        url=url[:2000],
                        prediction=result['prediction'],
                        confidence=result['confidence'],
                        risk_score=result['risk_score'],
                        model_used=model,
                        indicators=_json.dumps(result.get('indicators', [])),
                        user_id=current_user.id,
                    )
                    db.session.add(scan_row)
                except Exception as e:
                    results.append({'url': url, 'error': str(e),
                                    'prediction': 'error', 'risk_score': 0})

            db.session.commit()

            AuditLog.log(
                user_id=current_user.id,
                action='bulk_url_scan',
                details=f"Scanned {len(urls)} URLs via bulk scanner (model={model})",
                ip_address=request.remote_addr,
            )

        stats = _summary(results) if results else None
        return render_template('bulk_scan/index.html',
                               results=results, stats=stats, error=error,
                               submitted=True, model=model)

    return render_template('bulk_scan/index.html', results=[], stats=None,
                           error=None, submitted=False)


@bulk_bp.route('/export', methods=['POST'])
@login_required
def export_csv():
    """Export bulk scan results as CSV download."""
    import json as _json
    raw_results = request.form.get('results_json', '[]')
    try:
        results = _json.loads(raw_results)
    except Exception:
        results = []

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['URL', 'Prediction', 'Risk Score', 'Confidence', 'Model', 'Indicators'])
    for r in results:
        writer.writerow([
            r.get('url', ''),
            r.get('prediction', ''),
            r.get('risk_score', ''),
            r.get('confidence', ''),
            r.get('model_used', ''),
            '; '.join(r.get('indicators', [])),
        ])

    output = make_response(si.getvalue())
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    output.headers['Content-Disposition'] = f'attachment; filename=phishguard_bulk_{ts}.csv'
    output.headers['Content-type'] = 'text/csv'
    return output


@bulk_bp.route('/api', methods=['POST'])
@login_required
def api_bulk():
    """JSON API endpoint for bulk scanning."""
    data  = request.get_json(silent=True) or {}
    urls  = data.get('urls', [])
    model = data.get('model', 'random_forest')

    if not isinstance(urls, list) or not urls:
        return jsonify({'error': 'urls must be a non-empty list'}), 400
    if len(urls) > MAX_URLS:
        return jsonify({'error': f'Maximum {MAX_URLS} URLs allowed'}), 400

    results = []
    for url in urls:
        try:
            r = predict_url(str(url).strip(), model)
            r['url'] = url
            results.append(r)
        except Exception as e:
            results.append({'url': url, 'error': str(e), 'prediction': 'error'})

    phishing = sum(1 for r in results if r.get('prediction') == 'phishing')
    return jsonify({
        'status': 'ok',
        'total': len(results),
        'phishing_count': phishing,
        'legitimate_count': len(results) - phishing,
        'results': results,
    })


def _summary(results):
    total     = len(results)
    phishing  = sum(1 for r in results if r.get('prediction') == 'phishing')
    errors    = sum(1 for r in results if r.get('prediction') == 'error')
    avg_risk  = (sum(r.get('risk_score', 0) for r in results) / total) if total else 0
    return {
        'total': total, 'phishing': phishing,
        'legitimate': total - phishing - errors,
        'errors': errors,
        'avg_risk': round(avg_risk, 1),
    }

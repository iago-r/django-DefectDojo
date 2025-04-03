import logging

from django.core.paginator import Paginator
from django.http import HttpRequest
from django.shortcuts import render
from django.views import View

from dojo.filters import ProblemFilter, ProblemFindingFilter
from dojo.forms import FindingBulkUpdateForm
from dojo.models import Finding, Global_Role
from dojo.problem.redis import SEVERITY_ORDER, dict_problems_findings
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


class ListProblems(View):
    filter_name = "All"

    def get_template(self):
        return "dojo/problems_list.html"

    def order_field(self, request: HttpRequest, problems_findings_list):
        order_field = request.GET.get("o")
        if order_field:
            reverse_order = order_field.startswith("-")
            if reverse_order:
                order_field = order_field[1:]
            if order_field == "name":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: x.name, reverse=reverse_order)
            elif order_field == "title":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: x.title, reverse=reverse_order)
            elif order_field == "found_by":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: x.found_by.count(), reverse=reverse_order)
            elif order_field == "findings_count":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: len(x.finding_ids), reverse=reverse_order)
            elif order_field == "total_script_ids":
                problems_findings_list = sorted(problems_findings_list, key=lambda x: len(x.script_ids), reverse=reverse_order)
        return problems_findings_list

    def filters(self, request: HttpRequest):
        name_filter = request.GET.get("name", "").lower()
        min_severity_filter = request.GET.get("severity")
        script_id_filter = request.GET.get("script_id")
        engagement_filter = request.GET.getlist("engagement")
        product_filter = request.GET.getlist("product")
        return name_filter, min_severity_filter, script_id_filter, engagement_filter, product_filter

    def filter_problem(self, problem, request: HttpRequest):
        name_filter, min_severity_filter, script_id_filter, engagement_filter, product_filter = self.filters(request)
        add_problem = True
        if name_filter and name_filter not in problem.name.lower():
            add_problem = False
        if min_severity_filter and SEVERITY_ORDER.get(problem.severity) < SEVERITY_ORDER[min_severity_filter]:
            add_problem = False
        if script_id_filter and not any(script_id_filter in script_id for script_id in problem.script_ids):
            add_problem = False
        if engagement_filter and not Finding.objects.filter(id__in=problem.finding_ids, test__engagement__id__in=engagement_filter).exists():
            add_problem = False
        if product_filter and not Finding.objects.filter(id__in=problem.finding_ids, test__engagement__product__id__in=product_filter).exists():
            add_problem = False
        return add_problem

    def get_problems_map(self):
        problems_map, _ = dict_problems_findings()
        return problems_map

    def get_problems(self, request: HttpRequest):
        list_problem = []
        for _, problem in self.problems_map.items():
            if self.filter_problem(problem, request):
                list_problem.append(problem)
        return self.order_field(request, list_problem)

    def paginate_queryset(self, queryset, request: HttpRequest):
        page_size = request.GET.get("page_size", 25)  # Default is 25
        paginator = Paginator(queryset, page_size)
        page_number = request.GET.get("page")
        return paginator.get_page(page_number)

    def get(self, request: HttpRequest):
        global_role = Global_Role.objects.filter(user=request.user).first()
        if request.user.is_superuser or (global_role and global_role.role):
            self.problems_map = self.get_problems_map()
            problems = self.get_problems(request)
            paginated_problems = self.paginate_queryset(problems, request)
        else:
            paginated_problems = None

        context = {
            "filter_name": self.filter_name,
            "filtered": ProblemFilter(request.GET),
            "problems": paginated_problems,
        }

        add_breadcrumb(title="Problems", top_level=not len(request.GET), request=request)
        return render(request, self.get_template(), context)


class ListOpenProblems(ListProblems):
    filter_name = "Open"

    def get_problems(self, request: HttpRequest):
        list_problem = []
        active_findings = set(
            Finding.objects.filter(id__in=[fid for p in self.problems_map.values() for fid in p.finding_ids], active=True)
            .values_list("id", flat=True),
        )
        for _, problem in self.problems_map.items():
            if any(finding_id in active_findings for finding_id in problem.finding_ids):
                if self.filter_problem(problem, request):
                    list_problem.append(problem)
        return self.order_field(request, list_problem)


class ListClosedProblems(ListProblems):
    filter_name = "Closed"

    def get_problems(self, request: HttpRequest):
        list_problem = []
        active_findings = set(
            Finding.objects.filter(id__in=[fid for p in self.problems_map.values() for fid in p.finding_ids], active=True)
            .values_list("id", flat=True),
        )
        for _, problem in self.problems_map.items():
            if not any(finding_id in active_findings for finding_id in problem.finding_ids):
                if self.filter_problem(problem, request):
                    list_problem.append(problem)
        return self.order_field(request, list_problem)


class ProblemFindings(ListProblems):
    def get_template(self):
        return "dojo/problem_findings.html"

    def filters(self, request: HttpRequest):
        name_filter = request.GET.get("name", "").lower()
        severity_filter = request.GET.getlist("severity")
        script_id_filter = request.GET.get("script_id")
        reporter_filter = request.GET.getlist("reporter")
        status_filter = request.GET.get("status")
        engagement_filter = request.GET.getlist("engagement")
        product_filter = request.GET.getlist("product")
        return name_filter, severity_filter, script_id_filter, reporter_filter, status_filter, engagement_filter, product_filter

    def filter_findings(self, findings, request: HttpRequest):
        name_filter, severity_filter, script_id_filter, reporter_filter, status_filter, engagement_filter, product_filter = self.filters(request)
        if name_filter:
            findings = findings.filter(title__icontains=name_filter)
        if severity_filter:
            findings = findings.filter(severity__in=severity_filter)
        if script_id_filter:
            findings = findings.filter(vuln_id_from_tool__icontains=script_id_filter)
        if reporter_filter:
            findings = findings.filter(reporter__id__in=reporter_filter)
        if status_filter:
            findings = findings.filter(active=status_filter == "Yes")
        if engagement_filter:
            findings = findings.filter(test__engagement__id__in=engagement_filter)
        if product_filter:
            findings = findings.filter(test__engagement__product__id__in=product_filter)
        return findings

    def get_findings(self, request: HttpRequest):
        problem = self.problems_map.get(self.problem_id)

        # When the problem not exists, or the findings was changed for severity=Info
        if not problem:
            return None, []

        list_findings = problem.finding_ids
        findings = Finding.objects.filter(id__in=list_findings)
        findings = self.filter_findings(findings, request)
        return problem.name, self.order_field(request, findings)

    def get(self, request: HttpRequest, problem_id: int):
        self.problem_id = problem_id
        global_role = Global_Role.objects.filter(user=request.user).first()
        if request.user.is_superuser or (global_role and global_role.role):
            self.problems_map = self.get_problems_map()
            problem_name, findings = self.get_findings(request)
            paginated_findings = self.paginate_queryset(findings, request)
        else:
            problem_name, paginated_findings = None, None

        context = {
            "problem": problem_name,
            "filtered": ProblemFindingFilter(request.GET),
            "problem_id": self.problem_id,
            "findings": paginated_findings,
            "bulk_edit_form": FindingBulkUpdateForm(request.GET),
        }

        add_breadcrumb(title="Problems", top_level=not len(request.GET), request=request)
        return render(request, self.get_template(), context)

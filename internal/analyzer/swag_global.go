package analyzer

import (
	"go/ast"
	"sort"

	gingrammar "github.com/sagnikhaldar/gin-recon/internal/analyzer/gin"
	"github.com/sagnikhaldar/gin-recon/internal/model"
	"golang.org/x/tools/go/packages"
)

func collectSwagGlobalDocumentation(pkgs []*packages.Package) *model.APIDocumentation {
	var docs []*model.APIDocumentation
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			docs = append(docs, swagGlobalsInFile(file)...)
		}
	}
	return mergeGlobalDocumentation(docs)
}

func swagGlobalsInFile(file *ast.File) []*model.APIDocumentation {
	var docs []*model.APIDocumentation
	for _, group := range file.Comments {
		if d := gingrammar.ParseSwagGlobalAnnotations(group); d != nil {
			docs = append(docs, d)
		}
	}
	return docs
}

func mergeGlobalDocumentation(docs []*model.APIDocumentation) *model.APIDocumentation {
	if len(docs) == 0 {
		return nil
	}
	out := &model.APIDocumentation{Evidence: model.DocumentationEvidence{Source: "swag", Status: "declared"}, SecurityDefinitions: map[string]model.DocumentedSecurityScheme{}, Extensions: map[string]any{}, Fields: map[string]model.DocumentationEvidence{}}
	set := func(field, incoming, label string) string {
		if incoming == "" {
			return field
		}
		if field != "" && field != incoming {
			out.Issues = append(out.Issues, model.SwagIssue{Directive: label, Message: "conflicting global declarations; deterministic last declaration retained"})
		}
		return incoming
	}
	for _, d := range docs {
		out.Title = set(out.Title, d.Title, "@title")
		out.Version = set(out.Version, d.Version, "@version")
		out.Description = set(out.Description, d.Description, "@description")
		out.TermsOfService = set(out.TermsOfService, d.TermsOfService, "@termsOfService")
		out.ContactName = set(out.ContactName, d.ContactName, "@contact.name")
		out.ContactURL = set(out.ContactURL, d.ContactURL, "@contact.url")
		out.ContactEmail = set(out.ContactEmail, d.ContactEmail, "@contact.email")
		out.LicenseName = set(out.LicenseName, d.LicenseName, "@license.name")
		out.LicenseURL = set(out.LicenseURL, d.LicenseURL, "@license.url")
		out.Host = set(out.Host, d.Host, "@host")
		out.BasePath = set(out.BasePath, d.BasePath, "@basePath")
		out.Schemes = appendUniqueStrings(out.Schemes, d.Schemes...)
		out.Tags = append(out.Tags, d.Tags...)
		out.Security = append(out.Security, d.Security...)
		out.Issues = append(out.Issues, d.Issues...)
		for k, v := range d.SecurityDefinitions {
			if prior, ok := out.SecurityDefinitions[k]; ok && prior.Type != v.Type {
				out.Issues = append(out.Issues, model.SwagIssue{Directive: "@securityDefinitions", Message: "conflicting definition " + k + "; deterministic last declaration retained"})
			}
			out.SecurityDefinitions[k] = v
		}
		for k, v := range d.Extensions {
			out.Extensions[k] = v
		}
		for k, v := range d.Fields {
			out.Fields[k] = v
		}
	}
	sort.SliceStable(out.Tags, func(i, j int) bool { return out.Tags[i].Name < out.Tags[j].Name })
	if len(out.SecurityDefinitions) == 0 {
		out.SecurityDefinitions = nil
	}
	if len(out.Extensions) == 0 {
		out.Extensions = nil
	}
	if len(out.Fields) == 0 {
		out.Fields = nil
	}
	return out
}

func appendUniqueStrings(dst []string, values ...string) []string {
	seen := map[string]bool{}
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range values {
		if v != "" && !seen[v] {
			dst = append(dst, v)
			seen[v] = true
		}
	}
	return dst
}
